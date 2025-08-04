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
from sqlalchemy import desc, and_, or_
from flask_mail import Mail, Message as EmailMessage
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

LINE_ACCESS_TOKEN = "O02yXH2dlIyu9da3bJPfhtHTZYkDJR/wy1TnWj5ZAgBUr0zfiNrY9mC3qm5nEWyILuI+rcVftmsvsQZp+AB8Hf6f5UmDosjtkQY0ufX+JrVwa3i+UwlAXa7UvBQ/JBef2pRD4wJ3QttJyLn1nfh1dQdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # ควรเปลี่ยนเป็นค่าที่ปลอดภัยใน production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token หมดอายุใน 24 ชั่วโมง
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
jwt = JWTManager(app)

# Email Configuration - Office 365 (webmaster@git.or.th)
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'webmaster@git.or.th'
app.config['MAIL_PASSWORD'] = '2566#Web@th'
app.config['MAIL_DEFAULT_SENDER'] = 'webmaster@git.or.th'
mail = Mail(app)

# Alert recipient configuration
ALERT_RECIPIENT_EMAIL = 'it@git.or.th'
ALERT_RECIPIENT_NAME = 'IT Support'

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
DB_PASSWORD = 'npg_4xWvNOq1rnBI'
DB_HOST = 'ep-lucky-recipe-a1yjayui-pooler.ap-southeast-1.aws.neon.tech'
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
    ticket_id = db.Column(db.String, nullable=True)  # Allow messages without tickets
    user_id = db.Column(db.String, nullable=False)   # LINE User ID or similar
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
    pin = db.Column(db.String(10), nullable=False)  # รหัส PIN (no unique constraint - all users use 000000)
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

# New models for Email Alert System and Enhanced User Management
class EmailAlert(db.Model):
    __tablename__ = 'email_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # 'new_ticket', 'overdue_ticket'
    ticket_id = db.Column(db.String, db.ForeignKey('tickets.ticket_id'), nullable=True)
    recipient_email = db.Column(db.String(100), nullable=False)
    recipient_name = db.Column(db.String(100), nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'sent', 'failed'
    error_message = db.Column(db.Text, nullable=True)
    retry_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'ticket_id': self.ticket_id,
            'recipient_email': self.recipient_email,
            'recipient_name': self.recipient_name,
            'subject': self.subject,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'status': self.status,
            'error_message': self.error_message,
            'retry_count': self.retry_count
        }

class EmailTemplate(db.Model):
    __tablename__ = 'email_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    template_type = db.Column(db.String(50), unique=True, nullable=False)  # 'new_ticket', 'overdue_ticket'
    subject_template = db.Column(db.String(200), nullable=False)
    body_template = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'template_type': self.template_type,
            'subject_template': self.subject_template,
            'body_template': self.body_template,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class UserPermission(db.Model):
    __tablename__ = 'user_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    permission_name = db.Column(db.String(50), nullable=False)  # 'view_tickets', 'edit_tickets', 'delete_tickets', 'manage_users', 'receive_email_alerts'
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='permissions')
    granted_by_user = db.relationship('User', foreign_keys=[granted_by])
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'permission_name': self.permission_name,
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat() if self.granted_at else None,
            'granted_by_name': self.granted_by_user.name if self.granted_by_user else None
        }

class AlertSettings(db.Model):
    __tablename__ = 'alert_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(50), unique=True, nullable=False)  # 'new_ticket_alert_enabled', 'overdue_days_threshold'
    setting_value = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    updated_by_user = db.relationship('User', foreign_keys=[updated_by])
    
    def to_dict(self):
        return {
            'id': self.id,
            'setting_name': self.setting_name,
            'setting_value': self.setting_value,
            'description': self.description,
            'updated_by': self.updated_by,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by_name': self.updated_by_user.name if self.updated_by_user else None
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

# Email Alert System Functions
def send_email_alert(recipient_email, recipient_name, subject, body, alert_type, ticket_id=None):
    """Send email alert and log to database"""
    try:
        # Create email alert record
        email_alert = EmailAlert(
            alert_type=alert_type,
            ticket_id=ticket_id,
            recipient_email=recipient_email,
            recipient_name=recipient_name,
            subject=subject,
            body=body,
            status='pending'
        )
        db.session.add(email_alert)
        db.session.commit()
        
        
        if send_smtp_email(recipient_email, subject, body):
            email_alert.status = 'sent'
            logger.info(f"Email alert sent successfully to {recipient_email}")
        else:
            email_alert.status = 'failed'
            email_alert.error_message = 'SMTP send failed'
            logger.error(f"Failed to send email alert to {recipient_email}")
        
        db.session.commit()
        return email_alert.status == 'sent'
        
    except Exception as e:
        logger.error(f"Error sending email alert: {str(e)}")
        db.session.rollback()
        if 'email_alert' in locals():
            email_alert.status = 'failed'
            email_alert.error_message = str(e)
            db.session.commit()
        return False

def send_smtp_email(recipient_email, subject, body):
    """Send email using SMTP"""
    try:
      
        smtp_server = app.config.get('MAIL_SERVER')
        smtp_port = app.config.get('MAIL_PORT')
        smtp_username = app.config.get('MAIL_USERNAME')
        smtp_password = app.config.get('MAIL_PASSWORD')
       
        if smtp_password:
            smtp_password = smtp_password.replace(' ', '')  
        sender_email = app.config.get('MAIL_DEFAULT_SENDER')
        
        if not all([smtp_server, smtp_username, smtp_password, sender_email]):
            logger.error("Email configuration incomplete")
            return False
        
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email
        
        # Create HTML body
        html_body = f"""
        <html>
          <body>
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background-color: #005BBB; color: white; padding: 20px; text-align: center;">
                <h1>🎫 Ticket Management System</h1>
              </div>
              <div style="padding: 20px; background-color: #f9f9f9;">
                {body.replace(chr(10), '<br>')}
              </div>
              <div style="background-color: #e9e9e9; padding: 10px; text-align: center; font-size: 12px; color: #666;">
                <p>This is an automated message from the Ticket Management System</p>
              </div>
            </div>
          </body>
        </html>
        """
        
  
        part1 = MIMEText(body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if app.config.get('MAIL_USE_TLS'):
                server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        
        return True
        
    except Exception as e:
        logger.error(f"SMTP error: {str(e)}")
        return False

def get_all_users_for_alerts():
    """Get single user who should receive email alerts"""
    try:
       
        ALERT_EMAIL = "it@git.or.th"  
        ALERT_NAME = "ทีม IT"  
        
       
        class AlertRecipient:
            def __init__(self, email, name):
                self.email = email
                self.name = name
        
        return [AlertRecipient(ALERT_EMAIL, ALERT_NAME)]
        
    except Exception as e:
        logger.error(f"Error getting users for alerts: {str(e)}")
        return []

def check_and_send_overdue_alerts():
    """Check for overdue tickets and send email alerts with correct frequency to it@gi.or.th"""
    try:
        total_sent = 0
        current_time = datetime.utcnow()
        current_date = current_time.date()
        
        # Get cache key for tracking sent alerts to prevent spam
        cache_key = f'overdue_alerts_sent_{current_date.strftime("%Y%m%d")}'
        sent_today = cache.get(cache_key) or set()
        
        # Get all overdue tickets (New/Pending status, exclude information type)
        overdue_tickets = Ticket.query.filter(
            and_(
                Ticket.status.in_(['New', 'Pending']),
                or_(Ticket.type.is_(None), Ticket.type != 'information')
            )
        ).all()
        
        for ticket in overdue_tickets:
            try:
                days_overdue = (current_time - ticket.created_at).days
                
                # Skip if not overdue yet
                if days_overdue < 1:
                    continue
                
                # Determine alert frequency based on days overdue
                should_send = False
                frequency_desc = ''
                
                if 1 <= days_overdue < 3:
                    # ค้าง 1-2 วัน: แจ้งวันละครั้ง
                    should_send = True
                    frequency_desc = 'วันละครั้ง'
                elif 3 <= days_overdue < 5:
                    # ค้าง 3-4 วัน: แจ้ง 2 วันครั้ง
                    should_send = (days_overdue % 2 == 1)  # วันที่ 3, 5, 7, 9...
                    frequency_desc = '2 วันครั้ง'
                elif days_overdue >= 5:
                    # ค้าง 5+ วัน: แจ้ง 7 วันครั้ง
                    should_send = (days_overdue % 7 == 5)  # วันที่ 5, 12, 19, 26...
                    frequency_desc = '7 วันครั้ง'
                
                # Check if already sent today to prevent spam
                alert_key = f"{ticket.ticket_id}_{days_overdue}"
                if alert_key in sent_today:
                    continue
                
                if should_send:
                    # Create email content
                    subject = f"[Ticket #{ticket.ticket_id}] Ticket ค้าง {days_overdue} วัน - {ticket.name or 'N/A'} ({frequency_desc})"
                    
                    body = f'''เรียน ทีม IT,

Ticket ต่อไปนี้ค้างเป็นเวลา {days_overdue} วัน (แจ้งเตือน{frequency_desc}):

📋 รหัสทิกเก็ต: {ticket.ticket_id}
👤 ชื่อลูกค้า: {ticket.name or 'N/A'}
📧 อีเมล: {ticket.email or 'N/A'}
📞 เบอร์โทร: {ticket.phone or 'N/A'}
🏢 แผนก: {ticket.department or 'N/A'}
📝 ประเภท: {ticket.type or 'N/A'}
📅 วันนัดหมาย: {ticket.appointment or 'N/A'}
🔖 กลุ่ม: {ticket.report or 'N/A'}
🏷️ กลุ่มย่อย: {getattr(ticket, 'subgroup', None) or 'N/A'}
📄 รายงาน: {ticket.report or 'N/A'}
🎯 ความต้องการ: {ticket.requested or 'N/A'}
📅 วันที่สร้าง: {ticket.created_at.strftime('%d/%m/%Y %H:%M') if ticket.created_at else 'N/A'}
🔄 สถานะปัจจุบัน: {ticket.status}
⏰ ค้างมาแล้ว: {days_overdue} วัน
🔔 ความถี่การแจ้งเตือน: {frequency_desc}

กรุณาดำเนินการตรวจสอบและอัปเดตสถานะ

ขอบคุณครับ'''
                    
                    # Send email directly to it@gi.or.th
                    send_email_alert(
                        recipient_email=ALERT_RECIPIENT_EMAIL,
                        recipient_name=ALERT_RECIPIENT_NAME,
                        subject=subject,
                        body=body,
                        alert_type=f'overdue_ticket_{days_overdue}d',
                        ticket_id=ticket.ticket_id
                    )
                    
                    # Mark as sent to prevent spam
                    sent_today.add(alert_key)
                    total_sent += 1
                    
                    logger.info(f"Overdue alert sent for ticket: {ticket.ticket_id} ({days_overdue} days, {frequency_desc})")
                    
            except Exception as ticket_error:
                logger.error(f"Error processing overdue ticket {ticket.ticket_id}: {str(ticket_error)}")
        
        # Cache sent alerts for today to prevent duplicates
        cache.set(cache_key, sent_today, timeout=86400)  # 24 hours
        
        logger.info(f"Overdue ticket alerts process completed. Total sent: {total_sent} alerts")
        
    except Exception as e:
        logger.error(f"Error checking and sending overdue alerts: {str(e)}")

def send_new_ticket_alerts(ticket):
    """Send email alerts for new tickets"""
    try:
        print(f"📧 DEBUG: Starting email alert for ticket {ticket.ticket_id}")
        
        # Skip email alerts for information type tickets
        if ticket.type and ticket.type.lower() == 'information':
            print(f"ℹ️ DEBUG: Skipping email alert for information type ticket {ticket.ticket_id}")
            return
        
        # Create email content directly
        subject = f"[Ticket #{ticket.ticket_id}] ทิกเก็ตใหม่จาก {ticket.name or 'N/A'}"
        
        body = f'''เรียน ทีม IT,

มีทิกเก็ตใหม่เข้ามาในระบบ:

📋 รหัสทิกเก็ต: {ticket.ticket_id}
👤 ชื่อลูกค้า: {ticket.name or 'N/A'}
📧 อีเมล: {ticket.email or 'N/A'}
📞 เบอร์โทร: {ticket.phone or 'N/A'}
🏢 แผนก: {ticket.department or 'N/A'}
📝 ประเภท: {ticket.type or 'N/A'}
📅 วันนัดหมาย: {ticket.appointment or 'N/A'}
🔖 กลุ่ม: {ticket.report or 'N/A'}
🏷️ กลุ่มย่อย: {getattr(ticket, 'subgroup', None) or 'N/A'}
📄 รายงาน: {ticket.report or 'N/A'}
🎯 ความต้องการ: {ticket.requested or 'N/A'}
📅 วันที่สร้าง: {ticket.created_at.strftime('%d/%m/%Y %H:%M') if ticket.created_at else 'N/A'}

กรุณาเข้าสู่ระบบเพื่อดำเนินการต่อไป

ขอบคุณครับ'''
        
        # Send email directly to it@gi.or.th
        print(f"📨 DEBUG: Sending email to {ALERT_RECIPIENT_EMAIL} ({ALERT_RECIPIENT_NAME})")
        try:
            result = send_email_alert(
                recipient_email=ALERT_RECIPIENT_EMAIL,
                recipient_name=ALERT_RECIPIENT_NAME,
                subject=subject,
                body=body,
                alert_type='new_ticket',
                ticket_id=ticket.ticket_id
            )
            print(f"✅ DEBUG: New ticket email sent successfully to {ALERT_RECIPIENT_EMAIL}")
        except Exception as send_error:
            print(f"❌ DEBUG: Failed to send new ticket email: {str(send_error)}")
        
        print(f"🎉 DEBUG: New ticket alerts process completed for ticket {ticket.ticket_id}")
        
    except Exception as e:
        logger.error(f"Error sending new ticket alerts: {str(e)}")

        logger.error(f"Error checking and sending overdue alerts: {str(e)}")
def check_and_alert_new_tickets(tickets):
    """Check for new tickets and send email alerts"""
    try:
        
        cache_key = 'alerted_ticket_ids'
        alerted_ticket_ids = cache.get(cache_key) or set()
        
        new_tickets_found = []
        
    
        for ticket in tickets:
            if ticket.ticket_id not in alerted_ticket_ids:
                new_tickets_found.append(ticket)
                alerted_ticket_ids.add(ticket.ticket_id)
        
     
        cache.set(cache_key, alerted_ticket_ids, timeout=86400)  # เก็บไว้ 24 ชั่วโมง
        
       
        if new_tickets_found:
            print(f"🔔 Found {len(new_tickets_found)} new tickets, sending email alerts...")
            
            for ticket in new_tickets_found:
                try:
                    print(f"📧 Sending alert for new ticket: {ticket.ticket_id}")
                    send_new_ticket_alerts(ticket)
                    print(f"✅ Alert sent for ticket: {ticket.ticket_id}")
                except Exception as email_error:
                    print(f"❌ Failed to send alert for ticket {ticket.ticket_id}: {str(email_error)}")
        else:
            print("ℹ️ No new tickets found")
            
    except Exception as e:
        print(f"❌ Error in check_and_alert_new_tickets: {str(e)}")
        logger.error(f"Error checking new tickets: {str(e)}")

@app.route('/api/clear-alert-cache', methods=['POST'])
@jwt_required()
def clear_alert_cache():
    """Clear the alerted tickets cache (for testing)"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        cache_key = 'alerted_ticket_ids'
        cache.delete(cache_key)
        
        return jsonify({
            'success': True, 
            'message': 'Alert cache cleared successfully. New tickets will trigger alerts again.'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-overdue-alerts', methods=['POST'])
@jwt_required()
def test_overdue_alerts():
    """Test overdue ticket alerts manually"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        
        check_and_send_overdue_alerts()
        
      
        cutoff_date = datetime.utcnow() - timedelta(days=3)
        overdue_count = Ticket.query.filter(
            and_(
                Ticket.created_at < cutoff_date,
                Ticket.status.in_(['New', 'Pending'])
            )
        ).count()
        
        return jsonify({
            'success': True,
            'message': f'Overdue alerts check completed. Found {overdue_count} overdue tickets (New/Pending status, older than 3 days).'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def has_permission(user, permission_name):
    """Check if user has specific permission"""
    try:
        if not user or not user.is_active:
            return False
        
        # Admin users have all permissions
        if user.role == 'admin':
            return True
        
        # Check specific permission
        permission = UserPermission.query.filter_by(
            user_id=user.id,
            permission_name=permission_name
        ).first()
        
        return permission is not None
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        return False

def send_textbox_message(user_id, message_text):
    """Send message to LINE user with error handling"""
    try:
        if not LINE_ACCESS_TOKEN:
            print("❌ LINE_ACCESS_TOKEN not configured")
            return False
            
        if not user_id:
            print("❌ user_id is empty")
            return False
            
        print(f"📤 Attempting to send LINE message to user_id: {user_id}")
        
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

        response = requests.post(url, headers=headers, json=payload, timeout=10)
        print(f"📱 LINE API response: {response.status_code} - {response.text[:200]}")
        
        if response.status_code == 200:
            print(f"✅ LINE message sent successfully to {user_id}")
            return True
        else:
            print(f"❌ LINE API error {response.status_code}: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"⏰ LINE API timeout for user_id: {user_id}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ LINE API request error for {user_id}: {str(e)}")
        return False
    except Exception as e:
        print(f"⚠️ Unexpected error in send_textbox_message: {str(e)}")
        return False

def notify_user(payload):
    
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
        'New': '#00BFFF',           
        'In Progress': '#0066FF',   
        'Pending': '#FF9900',       
        'Closed': '#00AA00',        
        'Cancelled': '#666666',     
        'On Hold': '#A020F0',      
        'Rejected': '#FF0000',     
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
    """Register new user with username, password, email, and name - uses standard PIN 000000"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON data'}), 400
        
        # Validate required fields (PIN is no longer required from user input)
        required_fields = ['username', 'password', 'email', 'name']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        username = data['username'].strip()
        password = data['password']
        email = data['email'].strip().lower()
        name = data['name'].strip()
        role = data.get('role', 'user')  # Default to 'user' role
        
        # Use standard PIN for all users
        standard_pin = '000000'
        
        # Validate input lengths and formats
        if len(username) < 3 or len(username) > 50:
            return jsonify({'error': 'Username must be between 3-50 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if '@' not in email or len(email) > 100:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if username or email already exists (no PIN check since all use same PIN)
        existing_user = User.query.filter(
            (User.username == username) | 
            (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'Username already exists'}), 409
            elif existing_user.email == email:
                return jsonify({'error': 'Email already exists'}), 409
        
        # Create new user with standard PIN
        new_user = User(
            username=username,
            email=email,
            pin=standard_pin,  # All users use standard PIN
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
                'role': role,
                'pin_used': 'standard_000000'
            },
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'name': new_user.name,
                'role': new_user.role,
                'pin': '000000',  # Show standard PIN to user
                'is_active': new_user.is_active
            }
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

# Add simplified activity-log endpoint for frontend compatibility
@app.route('/api/activity-log', methods=['POST'])
@jwt_required()
def log_activity():
    """Log user activity - simplified endpoint for frontend"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        action_type = data.get('action_type', 'unknown')
        description = data.get('description', '')
        ticket_id = data.get('ticket_id')
        
        # Create activity log entry
        activity_log = UserActivityLog(
            user_id=current_user.id,
            action_type=action_type,
            description=description,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            metadata={'ticket_id': ticket_id} if ticket_id else None
        )
        
        db.session.add(activity_log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Activity logged successfully'
        }), 200
        
    except Exception as e:
        print(f"Activity log error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to log activity', 'details': str(e)}), 500

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
        
       
        if target_user.id == current_user.id:
            return jsonify({'error': 'Cannot deactivate your own account'}), 400
        
      
        target_user.is_active = not target_user.is_active
        db.session.commit()
        
    
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


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    try:
     
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"authenticated": False, "message": "No token provided"}), 401
        
        
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
       
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(1000).all()
        
        
        check_and_alert_new_tickets(tickets)
        
    
        check_and_send_overdue_alerts()
        
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



@app.route('/create-ticket', methods=['GET', 'POST'])
@jwt_required()
def create_ticket():
    """Create a new ticket with user activity logging"""
    try:
      
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
      
        session = get_session_from_token()
        if not session or not session.pin_verified:
            return jsonify({'error': 'PIN verification required'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        ticket_id = data.get('ticket_id') or str(uuid.uuid4())
        if Ticket.query.get(ticket_id):
            return jsonify({"error": "Ticket ID already exists"}), 400

      
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
        
        
        print(f"🔔 DEBUG: Attempting to send email alerts for ticket {ticket_id}")
        try:
            send_new_ticket_alerts(new_ticket)
            print(f"✅ DEBUG: Email alert function completed for ticket {ticket_id}")
        except Exception as email_error:
            print(f"❌ DEBUG: Email alert failed: {str(email_error)}")
        
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
            print(f"🗑️ DEBUG: Deleting data for ticket_id: {ticket_id}")
            
            # Delete status logs
            logs_deleted = TicketStatusLog.query.filter_by(ticket_id=ticket_id).delete(synchronize_session=False)
            print(f"📄 DEBUG: Deleted {logs_deleted} status logs")
            
            # Delete messages using ticket_id field
            messages_deleted = Message.query.filter_by(ticket_id=ticket_id).delete(synchronize_session=False)
            print(f"💬 DEBUG: Deleted {messages_deleted} messages")
            
            # Delete email alerts related to this ticket
            try:
                alerts_deleted = EmailAlert.query.filter_by(ticket_id=ticket_id).delete(synchronize_session=False)
                print(f"📧 DEBUG: Deleted {alerts_deleted} email alerts")
            except Exception as alert_err:
                print(f"⚠️ WARNING: Could not delete email alerts: {alert_err}")
            
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

# Process textbox messages from tickets into messages table
@app.route('/api/process-textbox-messages', methods=['POST', 'OPTIONS'])
def process_textbox_messages():
    """ย้ายข้อความจาก textbox ในตาราง tickets ไปใส่ในตาราง messages แล้วลบ textbox"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        ticket_id = data.get('ticket_id')
        if not ticket_id:
            return jsonify({"error": "ticket_id is required"}), 400
        
        print(f"📦 ย้าย textbox ไป messages สำหรับ ticket: {ticket_id}")
        
        # หา ticket ที่มี textbox และ type = "information"
        ticket = Ticket.query.filter_by(ticket_id=ticket_id).first()
        if not ticket:
            return jsonify({"error": "ไม่พบ ticket"}), 404
        
        # ตรวจสอบว่า ticket มี type = "information" หรือไม่
        if ticket.type != "information":
            return jsonify({
                "message": f"ข้าม ticket นี้เพราะ type = '{ticket.type}' (รองรับเฉพาะ type = 'information')", 
                "processed": 0,
                "ticket_type": ticket.type
            })
        
        if not ticket.textbox or ticket.textbox.strip() == '':
            return jsonify({"message": "ไม่มี textbox ที่จะย้าย", "processed": 0})
        
        textbox_content = ticket.textbox.strip()
        print(f"📝 เนื้อหา textbox: {textbox_content[:100]}...")
        
        # สร้าง message ใหม่จาก textbox
        new_message = Message(
            ticket_id=ticket_id,
            user_id=ticket_id,  # ใช้ ticket_id เป็น user_id สำหรับข้อความจาก LINE
            admin_id=None,
            sender_type="user",
            message=textbox_content,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_message)
        print(f"✅ สร้าง message ใหม่แล้ว")
        
        # สร้าง notification
        user_name = ticket.name if ticket.name else f"User {ticket_id[:8]}..."
        notification = Notification(
            message=f"ข้อความใหม่จาก {user_name}: {textbox_content[:50]}...",
            sender_name=user_name,
            user_id=ticket_id,
            meta_data={
                "type": "textbox_message",
                "ticket_id": ticket_id,
                "user_name": user_name
            }
        )
        db.session.add(notification)
        print(f"✅ สร้าง notification แล้ว")
        
        # ลบ textbox หลังจากย้ายแล้ว
        ticket.textbox = None
        print(f"🗑️ ลบ textbox ออกจาก ticket แล้ว")
        
        db.session.commit()
        
        print(f"✅ ย้าย textbox ไป messages สำเร็จ สำหรับ ticket {ticket_id}")
        return jsonify({
            "success": True,
            "message": "ย้าย textbox ไป messages สำเร็จแล้ว",
            "processed": 1,
            "ticket_id": ticket_id,
            "moved_content": textbox_content[:100] + "..." if len(textbox_content) > 100 else textbox_content
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ ข้อผิดพลาดในการย้าย textbox: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/process-all-textbox-messages', methods=['POST', 'OPTIONS'])
def process_all_textbox_messages():
    """ย้ายข้อความจาก textbox ในตาราง tickets ทั้งหมดไปใส่ในตาราง messages แล้วลบ textbox"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        print(f"📦 เริ่มย้าย textbox ทั้งหมดไป messages...")
        
        # หา tickets ทั้งหมดที่มี textbox ไม่ว่าง และ type = "information"
        tickets_with_textbox = Ticket.query.filter(
            Ticket.textbox.isnot(None),
            Ticket.textbox != '',
            Ticket.type == 'information'
        ).all()
        
        if not tickets_with_textbox:
            print(f"ℹ️ ไม่พบ tickets ที่มี textbox")
            return jsonify({
                "success": True,
                "message": "ไม่พบ tickets ที่มี textbox ที่จะย้าย",
                "processed": 0,
                "ticket_ids": []
            })
        
        print(f"🔍 พบ {len(tickets_with_textbox)} tickets ที่มี textbox")
        
        processed_count = 0
        processed_tickets = []
        failed_tickets = []
        
        for ticket in tickets_with_textbox:
            try:
                if ticket.textbox and ticket.textbox.strip():
                    textbox_content = ticket.textbox.strip()
                    print(f"📝 กำลังย้าย textbox จาก ticket {ticket.ticket_id}: {textbox_content[:50]}...")
                    
                    # สร้าง message ใหม่จาก textbox
                    new_message = Message(
                        ticket_id=ticket.ticket_id,
                        user_id=ticket.ticket_id,  # ใช้ ticket_id เป็น user_id
                        admin_id=None,
                        sender_type="user",
                        message=textbox_content,
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(new_message)
                    
                    # สร้าง notification
                    user_name = ticket.name if ticket.name else f"User {ticket.ticket_id[:8]}..."
                    notification = Notification(
                        message=f"ข้อความใหม่จาก {user_name}: {textbox_content[:50]}...",
                        sender_name=user_name,
                        user_id=ticket.ticket_id,
                        meta_data={
                            "type": "textbox_message",
                            "ticket_id": ticket.ticket_id,
                            "user_name": user_name
                        }
                    )
                    db.session.add(notification)
                    
                    # ลบ textbox หลังจากย้ายแล้ว
                    ticket.textbox = None
                    
                    processed_count += 1
                    processed_tickets.append(ticket.ticket_id)
                    
                    print(f"✅ ย้าย textbox สำเร็จสำหรับ ticket {ticket.ticket_id}")
            except Exception as ticket_error:
                print(f"❌ ข้อผิดพลาดในการย้าย ticket {ticket.ticket_id}: {str(ticket_error)}")
                failed_tickets.append(ticket.ticket_id)
                continue
        
        db.session.commit()
        
        result_message = f"ย้าย textbox ไป messages สำเร็จ {processed_count} tickets"
        if failed_tickets:
            result_message += f", ล้มเหลว {len(failed_tickets)} tickets"
        
        print(f"✅ {result_message}")
        return jsonify({
            "success": True,
            "message": result_message,
            "processed": processed_count,
            "failed": len(failed_tickets),
            "ticket_ids": processed_tickets,
            "failed_ticket_ids": failed_tickets
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error processing all textbox messages: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Test endpoint to verify server is working
@app.route('/api/test-messages', methods=['GET', 'POST'])
def test_messages():
    print(f"🧪 DEBUG: /api/test-messages called with method {request.method}")
    if request.method == 'POST':
        data = request.get_json()
        print(f"📝 DEBUG: POST data received: {data}")
        return jsonify({"success": True, "message": "Test endpoint working", "received_data": data})
    else:
        return jsonify({"success": True, "message": "Test endpoint working - GET"})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    print(f"📨 Getting messages for user_id: {user_id}")
    
    # Auto-process textbox messages for this user_id before returning messages
    try:
        ticket = Ticket.query.filter_by(ticket_id=user_id).first()
        if ticket and ticket.textbox and ticket.textbox.strip():
            print(f"📦 Auto-processing textbox for ticket {user_id}: {ticket.textbox[:50]}...")
            
            # Create message from textbox content
            new_message = Message(
                ticket_id=user_id,
                user_id=user_id,
                admin_id=None,
                sender_type="user",
                message=ticket.textbox.strip(),
                timestamp=datetime.utcnow()
            )
            db.session.add(new_message)
            
            # Create notification
            user_name = ticket.name if ticket.name else f"User {user_id[:8]}..."
            notification = Notification(
                message=f"ข้อความใหม่จาก {user_name}: {ticket.textbox[:50]}...",
                sender_name=user_name,
                user_id=user_id,
                meta_data={
                    "type": "textbox_message",
                    "ticket_id": user_id,
                    "user_name": user_name
                }
            )
            db.session.add(notification)
            
            # Clear textbox after processing
            ticket.textbox = None
            db.session.commit()
            
            print(f"✅ Auto-processed textbox message for ticket {user_id}")
    except Exception as e:
        print(f"⚠️ Error auto-processing textbox: {str(e)}")
        db.session.rollback()
    
    # Get all messages for this user
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
    
    print(f"📋 Returning {len(result)} messages for user {user_id}")
    return jsonify(result)

@app.route('/api/messages', methods=['POST'])
def send_message():
    print(f"📨 DEBUG: /api/messages POST request received from {request.remote_addr}")
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        print(f"💬 DEBUG: Received message data: {data}")
        
        user_id = data.get('user_id')
        admin_id = data.get('admin_id')
        sender_type = data.get('sender_type')
        message = data.get('message')
        
        print(f"🔍 DEBUG: user_id={user_id}, sender_type={sender_type}, message_length={len(message) if message else 0}")
        
        if not user_id or not message:
            return jsonify({"error": "user_id and message are required"}), 400
        
        # Set default sender_type (ensure it's never None)
        if not sender_type or sender_type.strip() == '':
            sender_type = 'admin' if admin_id else 'user'
        
        # Ensure sender_type is valid
        if sender_type not in ['user', 'admin']:
            sender_type = 'user'  # Default fallback
        
        print(f"💬 DEBUG: Final sender_type={sender_type}")
        
        # Check if ticket exists BEFORE creating message
        ticket = Ticket.query.filter_by(ticket_id=user_id).first()
        print(f"🎫 DEBUG: Ticket found: {ticket is not None}")
        
        # Set user_name for display purposes
        if not ticket:
            print(f"⚠️ ไม่พบ ticket {user_id} - อนุญาตให้ส่งข้อความได้แต่ไม่สร้าง dummy ticket")
            user_name = f"User {user_id[:8]}..."
        else:
            user_name = ticket.name if ticket.name else "Unknown User"
        
        # Create message
        msg = Message(
            ticket_id=user_id if ticket else None,  # Only set ticket_id if ticket exists
            user_id=user_id,     # Keep for compatibility
            admin_id=admin_id,
            sender_type=sender_type,
            message=message
        )
        db.session.add(msg)
        
        # สร้าง notification เฉพาะเมื่อ user ส่งข้อความ และมี ticket ที่ถูกต้อง
        if sender_type == 'user' and ticket:
            notif_msg = f"ข้อความใหม่จาก {user_name}: {message[:50]}{'...' if len(message) > 50 else ''}"
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
            print(f"📢 สร้าง notification สำหรับข้อความจาก user: {user_name}")
        elif sender_type == 'admin':
            print(f"🔇 ไม่สร้าง notification สำหรับข้อความจาก admin")
        else:
            print(f"🔇 ไม่สร้าง notification เพราะไม่มี ticket ที่ถูกต้อง")
        
        db.session.commit()
        
      
        if sender_type == 'admin':
            try:
                line_success = send_textbox_message(user_id, message)
                if line_success:
                    print(f"✅ LINE message sent successfully to {user_id}")
                else:
                    print(f"❌ Failed to send LINE message to {user_id}")
            except Exception as line_error:
                print(f"⚠️ LINE message error for {user_id}: {str(line_error)}")
        
        return jsonify({
            "id": msg.id,
            "user_id": msg.user_id,
            "admin_id": msg.admin_id,
            "sender_type": msg.sender_type,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
            "success": True
        })
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ ERROR in send_message: {str(e)}")
        print(f"🔍 Full traceback: {error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500

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

# ================= EMAIL ALERT MANAGEMENT APIs =================

@app.route('/api/email-alerts', methods=['GET'])
@jwt_required()
def get_email_alerts():
    """Get email alert history"""
    try:
        user = get_user_from_token()
        if not user or not has_permission(user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        alert_type = request.args.get('type')
        status = request.args.get('status')
        
        query = EmailAlert.query
        
        if alert_type:
            query = query.filter(EmailAlert.alert_type == alert_type)
        if status:
            query = query.filter(EmailAlert.status == status)
        
        alerts = query.order_by(EmailAlert.sent_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'alerts': [alert.to_dict() for alert in alerts.items],
            'total': alerts.total,
            'pages': alerts.pages,
            'current_page': page
        })
        
    except Exception as e:
        logger.error(f"Error getting email alerts: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/email-templates', methods=['GET', 'POST', 'PUT'])
@jwt_required()
def manage_email_templates():
    """Manage email templates"""
    try:
        user = get_user_from_token()
        if not user or not has_permission(user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        if request.method == 'GET':
            templates = EmailTemplate.query.all()
            return jsonify([template.to_dict() for template in templates])
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing JSON data'}), 400
            
            required_fields = ['template_type', 'subject_template', 'body_template']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Check if template type already exists
            existing = EmailTemplate.query.filter_by(template_type=data['template_type']).first()
            if existing:
                return jsonify({'error': 'Template type already exists'}), 409
            
            template = EmailTemplate(
                template_type=data['template_type'],
                subject_template=data['subject_template'],
                body_template=data['body_template'],
                is_active=data.get('is_active', True)
            )
            
            db.session.add(template)
            db.session.commit()
            
            return jsonify(template.to_dict()), 201
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data or 'id' not in data:
                return jsonify({'error': 'Missing template ID'}), 400
            
            template = EmailTemplate.query.get(data['id'])
            if not template:
                return jsonify({'error': 'Template not found'}), 404
            
            # Update fields
            if 'subject_template' in data:
                template.subject_template = data['subject_template']
            if 'body_template' in data:
                template.body_template = data['body_template']
            if 'is_active' in data:
                template.is_active = data['is_active']
            
            db.session.commit()
            return jsonify(template.to_dict())
        
    except Exception as e:
        logger.error(f"Error managing email templates: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alert-settings', methods=['GET', 'POST', 'PUT'])
@jwt_required()
def manage_alert_settings():
    """Manage alert settings"""
    try:
        user = get_user_from_token()
        if not user or not has_permission(user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        if request.method == 'GET':
            settings = AlertSettings.query.all()
            return jsonify([setting.to_dict() for setting in settings])
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing JSON data'}), 400
            
            required_fields = ['setting_name', 'setting_value']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Check if setting already exists
            existing = AlertSettings.query.filter_by(setting_name=data['setting_name']).first()
            if existing:
                return jsonify({'error': 'Setting already exists'}), 409
            
            setting = AlertSettings(
                setting_name=data['setting_name'],
                setting_value=data['setting_value'],
                description=data.get('description'),
                updated_by=user.id
            )
            
            db.session.add(setting)
            db.session.commit()
            
            return jsonify(setting.to_dict()), 201
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data or 'id' not in data:
                return jsonify({'error': 'Missing setting ID'}), 400
            
            setting = AlertSettings.query.get(data['id'])
            if not setting:
                return jsonify({'error': 'Setting not found'}), 404
            
            # Update fields
            if 'setting_value' in data:
                setting.setting_value = data['setting_value']
            if 'description' in data:
                setting.description = data['description']
            
            setting.updated_by = user.id
            
            db.session.commit()
            return jsonify(setting.to_dict())
        
    except Exception as e:
        logger.error(f"Error managing alert settings: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ================= USER MANAGEMENT APIs =================

@app.route('/api/users', methods=['GET', 'POST'])
@jwt_required()
def manage_users():
    """Get all users or create new user"""
    try:
        user = get_user_from_token()
        if not user or not has_permission(user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        if request.method == 'GET':
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            role_filter = request.args.get('role')
            active_filter = request.args.get('active')
            
            query = User.query
            
            if role_filter:
                query = query.filter(User.role == role_filter)
            if active_filter is not None:
                query = query.filter(User.is_active == (active_filter.lower() == 'true'))
            
            users = query.order_by(User.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )
            
            return jsonify({
                'users': [user.to_dict() for user in users.items],
                'total': users.total,
                'pages': users.pages,
                'current_page': page
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing JSON data'}), 400
            
            required_fields = ['username', 'password', 'email', 'name']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Check if username or email already exists
            existing_user = User.query.filter(
                (User.username == data['username']) | 
                (User.email == data['email'])
            ).first()
            
            if existing_user:
                if existing_user.username == data['username']:
                    return jsonify({'error': 'Username already exists'}), 409
                elif existing_user.email == data['email']:
                    return jsonify({'error': 'Email already exists'}), 409
            
            # Create new user
            new_user = User(
                username=data['username'],
                email=data['email'],
                pin='000000',  # Standard PIN
                name=data['name'],
                role=data.get('role', 'user'),
                is_active=data.get('is_active', True)
            )
            new_user.set_password(data['password'])
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log activity
            log_user_activity(
                user_id=user.id,
                action_type='create_user',
                resource_type='user',
                resource_id=str(new_user.id),
                action_details={'created_user': new_user.username}
            )
            
            return jsonify(new_user.to_dict()), 201
        
    except Exception as e:
        logger.error(f"Error managing users: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_user_by_id(user_id):
    """Get, update, or delete specific user"""
    try:
        current_user = get_user_from_token()
        if not current_user or not has_permission(current_user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        if request.method == 'GET':
            return jsonify(target_user.to_dict())
        
        elif request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing JSON data'}), 400
            
            
            if 'name' in data:
                target_user.name = data['name']
            if 'email' in data:
               
                existing = User.query.filter(User.email == data['email'], User.id != user_id).first()
                if existing:
                    return jsonify({'error': 'Email already exists'}), 409
                target_user.email = data['email']
            if 'role' in data:
                target_user.role = data['role']
            if 'is_active' in data:
                target_user.is_active = data['is_active']
            if 'password' in data and data['password']:
                target_user.set_password(data['password'])
            
            db.session.commit()
            
            # Log activity
            log_user_activity(
                user_id=current_user.id,
                action_type='update_user',
                resource_type='user',
                resource_id=str(user_id),
                action_details={'updated_user': target_user.username}
            )
            
            return jsonify(target_user.to_dict())
        
        elif request.method == 'DELETE':
            # Prevent deleting self
            if target_user.id == current_user.id:
                return jsonify({'error': 'Cannot delete your own account'}), 400
            
            # Log activity before deletion
            log_user_activity(
                user_id=current_user.id,
                action_type='delete_user',
                resource_type='user',
                resource_id=str(user_id),
                action_details={'deleted_user': target_user.username}
            )
            
            db.session.delete(target_user)
            db.session.commit()
            
            return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error managing user {user_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>/permissions', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
def manage_user_permissions(user_id):
    """Manage user permissions"""
    try:
        current_user = get_user_from_token()
        if not current_user or not has_permission(current_user, 'manage_users'):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        if request.method == 'GET':
            permissions = UserPermission.query.filter_by(user_id=user_id).all()
            return jsonify([perm.to_dict() for perm in permissions])
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data or 'permission_name' not in data:
                return jsonify({'error': 'Missing permission_name'}), 400
            
            # Check if permission already exists
            existing = UserPermission.query.filter_by(
                user_id=user_id,
                permission_name=data['permission_name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Permission already granted'}), 409
            
            permission = UserPermission(
                user_id=user_id,
                permission_name=data['permission_name'],
                granted_by=current_user.id
            )
            
            db.session.add(permission)
            db.session.commit()
            
            # Log activity
            log_user_activity(
                user_id=current_user.id,
                action_type='grant_permission',
                resource_type='permission',
                resource_id=str(permission.id),
                action_details={
                    'user': target_user.username,
                    'permission': data['permission_name']
                }
            )
            
            return jsonify(permission.to_dict()), 201
        
        elif request.method == 'DELETE':
            data = request.get_json()
            if not data or 'permission_name' not in data:
                return jsonify({'error': 'Missing permission_name'}), 400
            
            permission = UserPermission.query.filter_by(
                user_id=user_id,
                permission_name=data['permission_name']
            ).first()
            
            if not permission:
                return jsonify({'error': 'Permission not found'}), 404
            
            # Log activity before deletion
            log_user_activity(
                user_id=current_user.id,
                action_type='revoke_permission',
                resource_type='permission',
                resource_id=str(permission.id),
                action_details={
                    'user': target_user.username,
                    'permission': data['permission_name']
                }
            )
            
            db.session.delete(permission)
            db.session.commit()
            
            return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error managing permissions for user {user_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500



# ================= DATABASE INITIALIZATION =================

def create_email_alert_tables():
    """Create email alert related tables"""
    try:
        with app.app_context():
            # Create all new tables
            db.create_all()
            
            # Initialize default email templates
            init_default_email_templates()
            
            # Initialize default alert settings
            init_default_alert_settings()
            
            logger.info("Email alert tables created successfully")
    except Exception as e:
        logger.error(f"Error creating email alert tables: {str(e)}")



def init_default_email_templates():
    """Initialize default email templates"""
    try:
        templates = [
            {
                'template_type': 'new_ticket',
                'subject_template': '[Ticket #{ticket_id}] ทิกเก็ตใหม่จาก {name}',
                'body_template': '''เรียน ผู้ใช้ระบบ,

มีทิกเก็ตใหม่เข้ามาในระบบ:

📋 รหัสทิกเก็ต: {ticket_id}
👤 ชื่อลูกค้า: {name}
📧 อีเมล: {email}
📞 เบอร์โทร: {phone}
🏢 แผนก: {department}
📝 ประเภท: {type}
📄 รายงาน: {report}
🎯 ความต้องการ: {requested}
📅 วันที่สร้าง: {created_at}

กรุณาเข้าสู่ระบบเพื่อดำเนินการต่อไป

ขอบคุณครับ'''
            },
            {
                'template_type': 'overdue_ticket',
                'subject_template': '⚠️ แจ้งเตือน: มีทิกเก็ตค้างคา {count} รายการ (เกิน {days} วัน)',
                'body_template': '''เรียน ผู้ใช้ระบบ,

มีทิกเก็ตที่ค้างคามานานเกิน {days} วัน จำนวน {count} รายการ:

{ticket_list}

กรุณาเข้าสู่ระบบเพื่อดำเนินการให้เสร็จสิ้น

วันที่ตรวจสอบ: {current_date}

ขอบคุณครับ'''
            }
        ]
        
        for template_data in templates:
            existing = EmailTemplate.query.filter_by(template_type=template_data['template_type']).first()
            if not existing:
                template = EmailTemplate(
                    template_type=template_data['template_type'],
                    subject_template=template_data['subject_template'],
                    body_template=template_data['body_template']
                )
                db.session.add(template)
        
        db.session.commit()
        logger.info("Default email templates initialized")
        
    except Exception as e:
        logger.error(f"Error initializing email templates: {str(e)}")
        db.session.rollback()

def init_default_alert_settings():
    """Initialize default alert settings"""
    try:
        settings = [
            {
                'setting_name': 'new_ticket_alert_enabled',
                'setting_value': 'true',
                'description': 'Enable email alerts for new tickets'
            },
            {
                'setting_name': 'overdue_alert_enabled',
                'setting_value': 'true',
                'description': 'Enable email alerts for overdue tickets'
            },
            {
                'setting_name': 'overdue_days_threshold',
                'setting_value': '3',
                'description': 'Number of days after which a ticket is considered overdue'
            }
        ]
        
        for setting_data in settings:
            existing = AlertSettings.query.filter_by(setting_name=setting_data['setting_name']).first()
            if not existing:
                setting = AlertSettings(
                    setting_name=setting_data['setting_name'],
                    setting_value=setting_data['setting_value'],
                    description=setting_data['description']
                )
                db.session.add(setting)
        
        db.session.commit()
        logger.info("Default alert settings initialized")
        
    except Exception as e:
        logger.error(f"Error initializing alert settings: {str(e)}")
        db.session.rollback()

@app.route('/api/simple-email-alerts', methods=['GET'])
def get_simple_email_alerts():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        status = request.args.get('status', '')
        date_from = request.args.get('dateFrom', '')
        date_to = request.args.get('dateTo', '')
        
       
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS email_alerts (
                id SERIAL PRIMARY KEY,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT,
                status TEXT DEFAULT 'sent',
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT
            )
        ''')
        
        # Query ข้อมูล
        query = "SELECT * FROM email_alerts WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = %s"
            params.append(status)
        if date_from:
            query += " AND sent_at >= %s"
            params.append(date_from)
        if date_to:
            query += " AND sent_at <= %s"
            params.append(date_to)
            
        query += " ORDER BY sent_at DESC LIMIT %s OFFSET %s"
        params.extend([per_page, (page - 1) * per_page])
        
        cur.execute(query, params)
        alerts = cur.fetchall()
        
        # แปลงเป็น dict
        columns = [desc[0] for desc in cur.description]
        result = [dict(zip(columns, row)) for row in alerts]
        
        conn.close()
        
        return jsonify({
            'alerts': result,
            'total': len(result),
            'page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def create_email_alert_tables():
    """Create email alert related tables and initialize default data"""
    try:
        # Create all tables
        db.create_all()
        
        # Initialize default email templates
        init_default_email_templates()
        
        # Initialize default alert settings
        init_default_alert_settings()
        
        logger.info("Email alert tables created and initialized")
        
    except Exception as e:
        logger.error(f"Error creating email alert tables: {str(e)}")

@app.route('/api/test-email', methods=['POST'])
@jwt_required()
def test_email():
    """Test email sending functionality"""
    try:
        current_user = get_user_from_token()
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        recipient_email = data.get('email', current_user.email)
        
        if not recipient_email:
            return jsonify({'error': 'No email address provided'}), 400
        
        # Test email content
        subject = 'ทดสอบระบบอีเมลแจ้งเตือน - Test Email Alert System'
        body = f'''เรียน {current_user.name},

นี่คือการทดสอบระบบอีเมลแจ้งเตือนของระบบ Ticket Management

✅ ระบบอีเมลทำงานปกติ
📧 อีเมลผู้ส่ง: {app.config['MAIL_USERNAME']}
📧 อีเมลผู้รับ: {recipient_email}
🕐 เวลาที่ส่ง: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

ขอบคุณครับ
ระบบ Ticket Management'''
        
        # Send test email
        success = send_smtp_email(recipient_email, subject, body)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {recipient_email}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email'
            }), 500
        
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Delete ticket endpoint
@app.route('/delete-ticket', methods=['POST'])
def delete_ticket_endpoint():
    """Delete a ticket and all related data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        ticket_id = data.get('ticket_id')
        if not ticket_id:
            return jsonify({"error": "ticket_id is required"}), 400
        
        # Delete related data and ticket
        try:
            print(f"🗑️ DEBUG: Deleting data for ticket_id: {ticket_id}")
            
            # Delete messages related to this ticket using ticket_id field
            messages_deleted = db.session.query(Message).filter(Message.ticket_id == ticket_id).delete()
            print(f"💬 DEBUG: Deleted {messages_deleted} messages")
            
            # Delete status logs related to this ticket
            logs_deleted = db.session.query(TicketStatusLog).filter(TicketStatusLog.ticket_id == ticket_id).delete()
            print(f"📄 DEBUG: Deleted {logs_deleted} status logs")
            
            # Delete the ticket itself
            ticket = Ticket.query.get(ticket_id)
            if ticket:
                db.session.delete(ticket)
            
            # Create notification about deletion (without auto-commit)
            notif = Notification(
                message=f"Ticket {ticket_id} has been deleted",
                timestamp=datetime.utcnow(),
                read=False,
                sender_name="system",
                user_id=ticket_id,
                meta_data={
                    "type": "ticket_deleted",
                    "ticket_id": ticket_id
                }
            )
            db.session.add(notif)
            
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "Ticket deleted successfully"
            })
            
        except Exception as delete_error:
            db.session.rollback()
            import traceback
            error_details = traceback.format_exc()
            print(f"❌ ERROR deleting ticket data: {str(delete_error)}")
            print(f"🔍 Delete traceback: {error_details}")
            return jsonify({"error": f"Failed to delete ticket: {str(delete_error)}", "details": error_details}), 500
        
    except Exception as e:
        db.session.rollback()
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ ERROR in delete_ticket_endpoint: {str(e)}")
        print(f"🔍 Full delete traceback: {error_details}")
        return jsonify({"error": str(e), "details": error_details}), 500

def setup_scheduler():
    """Setup background scheduler for overdue alerts"""
    try:
        scheduler = BackgroundScheduler()
        
        # Schedule overdue alerts check every day at 9:00 AM
        scheduler.add_job(
            func=check_and_send_overdue_alerts,
            trigger='cron',
            hour=9,
            minute=0,
            id='overdue_alerts_job'
        )
        
        scheduler.start()
        logger.info("Scheduler started for overdue alerts")
        
        # Ensure scheduler shuts down when app exits
        import atexit
        atexit.register(lambda: scheduler.shutdown())
        
    except Exception as e:
        logger.error(f"Error setting up scheduler: {str(e)}")

@app.route('/api/test-email', methods=['POST'])
@jwt_required(optional=True)
def test_email_sending():
    """Test email sending functionality"""
    try:
        data = request.get_json() or {}
        recipient_email = data.get('email', 'webmaster@git.or.th')
        subject = data.get('subject', 'Test Email from Ticket Management System')
        body = data.get('body', 'This is a test email to verify Office 365 SMTP configuration is working correctly.')
        
        # Test SMTP configuration
        smtp_config = {
            'server': app.config.get('MAIL_SERVER'),
            'port': app.config.get('MAIL_PORT'),
            'username': app.config.get('MAIL_USERNAME'),
            'sender': app.config.get('MAIL_DEFAULT_SENDER'),
            'use_tls': app.config.get('MAIL_USE_TLS'),
            'use_ssl': app.config.get('MAIL_USE_SSL')
        }
        
        # Send test email
        success = send_email_alert(
            recipient_email=recipient_email,
            recipient_name='Test Recipient',
            subject=subject,
            body=body,
            alert_type='test'
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {recipient_email}',
                'smtp_config': smtp_config
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email',
                'smtp_config': smtp_config
            }), 500
            
    except Exception as e:
        logger.error(f"Email test error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Email test failed'
        }), 500

@app.route('/api/email-config', methods=['GET'])
@jwt_required(optional=True)
def get_email_config():
    """Get current email configuration (without sensitive data)"""
    try:
        config = {
            'mail_server': app.config.get('MAIL_SERVER'),
            'mail_port': app.config.get('MAIL_PORT'),
            'mail_use_tls': app.config.get('MAIL_USE_TLS'),
            'mail_use_ssl': app.config.get('MAIL_USE_SSL'),
            'mail_username': app.config.get('MAIL_USERNAME'),
            'mail_default_sender': app.config.get('MAIL_DEFAULT_SENDER'),
            'password_configured': bool(app.config.get('MAIL_PASSWORD'))
        }
        
        return jsonify({
            'success': True,
            'config': config
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def migrate_messages_table():
    """Make ticket_id nullable in messages table"""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        
        # Check if ticket_id is already nullable
        cur.execute("""
            SELECT is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'messages' AND column_name = 'ticket_id'
        """)
        result = cur.fetchone()
        
        if result and result[0] == 'NO':
            print("🔧 Making ticket_id nullable in messages table...")
            cur.execute("ALTER TABLE messages ALTER COLUMN ticket_id DROP NOT NULL")
            conn.commit()
            print("✅ ticket_id is now nullable in messages table")
        else:
            print("ℹ️ ticket_id is already nullable in messages table")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error migrating messages table: {str(e)}")
        if 'conn' in locals():
            conn.close()


if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
        create_ticket_status_logs_table()
        create_email_alert_tables()
        migrate_messages_table()  # Fix ticket_id nullable issue
    
    setup_scheduler()
    
    app.run(host='0.0.0.0', port=5001, debug=False)