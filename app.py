from flask import Flask, jsonify, request
import requests
from flask_cors import CORS 
import psycopg2
import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime
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

LINE_ACCESS_TOKEN = "RF7HySsgh8pRmAW3UgwHu4fZ7WWyokBrrs1Ewx7tt8MJ47eFqlnZ4eOZnEg2UFZH++4ZW0gfRK/MLynU0kANOEq23M4Hqa6jdGGWeDO75TuPEEZJoHOw2yabnaSDOfhtXc9GzZdXW8qoVqFnROPhegdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # ควรเปลี่ยนเป็นค่าที่ปลอดภัยใน production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token หมดอายุใน 1 ชั่วโมง
jwt = JWTManager(app)

CORS(app)

DB_NAME = 'datagit'
DB_USER = 'git'
DB_PASSWORD = '4H9c9zbnSxqdrQVUY2ErAtJwzJINcfNn'
DB_HOST = 'dpg-d19qj8bipnbc739c4aq0-a.singapore-postgres.render.com'
DB_PORT = 5432

# Flask-SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Google Sheets config
SHEET_NAME = 'Tickets'  # ชื่อ Google Sheet ที่มีข้อมูล
WORKSHEET_NAME = 'Sheet1'  # หรือชื่อ sheet ที่มีข้อมูล
CREDENTIALS_FILE = 'credentials.json'

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


def sync_google_sheet_to_postgres():
    try:
        # 1. Connect to Google Sheets
        scope = ['https://spreadsheets.google.com/feeds', 
                'https://www.googleapis.com/auth/drive']
        
        # ตรวจสอบว่าไฟล์ credentials.json มีอยู่
        if not os.path.exists(CREDENTIALS_FILE):
            raise Exception(f"Credentials file {CREDENTIALS_FILE} not found")
            
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        
        # เปิด sheet ด้วยชื่อ
        try:
            sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)
            records = sheet.get_all_records()
        except gspread.exceptions.SpreadsheetNotFound:
            raise Exception(f"Google Sheet '{SHEET_NAME}' not found")
        except gspread.exceptions.WorksheetNotFound:
            raise Exception(f"Worksheet '{WORKSHEET_NAME}' not found")

        # 2. Connect to PostgreSQL
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
                host=DB_HOST, port=DB_PORT
            )
            cur = conn.cursor()
        except psycopg2.Error as e:
            raise Exception(f"Database connection error: {str(e)}")

        # ดึง ticket_id จาก Google Sheets
        sheet_ticket_ids = [str(row['Ticket ID']) for row in records if row.get('Ticket ID')]
        
        # 3. ลบข้อมูลใน Postgres ที่ไม่มีใน Google Sheets
        if sheet_ticket_ids:
            # ใช้ IN กับ list ของ ticket_ids
            cur.execute("""
                DELETE FROM tickets 
                WHERE ticket_id NOT IN %s
                AND ticket_id IS NOT NULL
            """, (tuple(sheet_ticket_ids),))
        else:
            # ถ้าไม่มีเหลือใน Google Sheets เลย ลบทั้งหมด
            cur.execute("DELETE FROM tickets;")

        # 4. Sync (insert/update) ข้อมูลใหม่
        textbox_updates = []
        for row in records:
            try:
                ticket_id = str(row.get('Ticket ID', ''))
                if not ticket_id:
                    continue

                current_textbox = None
                # ดึงข้อมูล textbox ปัจจุบันจาก PostgreSQL
                cur.execute("SELECT textbox FROM tickets WHERE ticket_id = %s", (ticket_id,))
                result = cur.fetchone()
                if result:
                    current_textbox = result[0] if result[0] else None
                
                new_textbox = str(row.get('TEXTBOX', '')) if row.get('TEXTBOX') else None
                
                # ตรวจสอบว่า textbox มีการเปลี่ยนแปลงและไม่ว่างเปล่า
                if new_textbox and new_textbox != current_textbox:
                    # ถ้าเป็นข้อความจาก User (ไม่ใช่จาก Admin)
                    if not new_textbox.startswith("Admin:"):
                        user_name = str(row.get('ชื่อ', 'Unknown')) if row.get('ชื่อ') else 'Unknown'
                        cur.execute("""
                            INSERT INTO messages (
                                ticket_id, sender_name, message, is_admin_message
                            ) VALUES (%s, %s, %s, %s)
                        """, (ticket_id, user_name, new_textbox, False))
                        message = f"New message from {user_name} for ticket {ticket_id}: {new_textbox}"
                        cur.execute("INSERT INTO notifications (message) VALUES (%s)", (message,))

                cur.execute("""
                    INSERT INTO tickets (
                        ticket_id, user_id, email, name, phone,
                        department, created_at, status, appointment,
                        requested, report, type, textbox
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (ticket_id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        email = EXCLUDED.email,
                        name = EXCLUDED.name,
                        phone = EXCLUDED.phone,
                        department = EXCLUDED.department,
                        created_at = EXCLUDED.created_at,
                        status = EXCLUDED.status,
                        appointment = EXCLUDED.appointment,
                        requested = EXCLUDED.requested,
                        report = EXCLUDED.report,
                        type = EXCLUDED.type,
                        textbox = CASE 
                            WHEN EXCLUDED.textbox != '' THEN EXCLUDED.textbox 
                            ELSE tickets.textbox 
                        END
                """, (
                    ticket_id,
                    row.get('User ID', ''),
                    row.get('อีเมล', ''),
                    row.get('ชื่อ', ''),
                    row.get('เบอร์ติดต่อ', ''),
                    row.get('แผนก', ''),
                    parse_datetime(row.get('วันที่แจ้ง', '')),
                    row.get('สถานะ', ''),
                    row.get('Appointment', ''),
                    row.get('Requeste', ''),
                    row.get('Report', ''),
                    row.get('Type', ''),
                    new_textbox
                ))
            except Exception as e:
                print(f"❌ Error syncing row: {row.get('Ticket ID', 'N/A')} - {e}")
        
        # เพิ่ม notification สำหรับ textbox ที่อัปเดต
        for update in textbox_updates:
            message = f"New message from {update['name']} for ticket {update['ticket_id']}: {update['message']}"
            cur.execute("INSERT INTO notifications (message) VALUES (%s)", (message,))

        # เพิ่ม notification สำหรับ ticket ใหม่
        new_tickets = []
        for row in records:
            ticket_id = str(row.get('Ticket ID', ''))
            if ticket_id:
                cur.execute("SELECT 1 FROM tickets WHERE ticket_id = %s", (ticket_id,))
                if not cur.fetchone():
                    new_tickets.append(row)
                    message = f"New ticket created: #{ticket_id} - {row.get('ชื่อ', '')} ({row.get('แผนก', '')})"
                    cur.execute("INSERT INTO notifications (message) VALUES (%s)", (message,))

        conn.commit()
        conn.close()
        return new_tickets
        
    except Exception as e:
        # จัดการข้อผิดพลาดและบันทึก log
        print(f"❌ Error in sync_google_sheet_to_postgres: {str(e)}")
        raise  # ส่งข้อผิดพลาดต่อไปเพื่อให้ Flask จัดการ

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

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' หรือ 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# สร้างตาราง users
def create_tables():
    db.create_all()
    
    # สร้างผู้ใช้ admin เริ่มต้นถ้ายังไม่มี
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')  # เปลี่ยนรหัสผ่านนี้ใน production!
        db.session.add(admin)
        db.session.commit()

# เพิ่ม route สำหรับ login
@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity={
        'username': user.username,
        'role': user.role
    })
    return jsonify(access_token=access_token), 200

# เพิ่ม route สำหรับตรวจสอบ token
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200





@app.route('/api/data')
@jwt_required()
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
                "Requeste": ticket.requested,
                "Report": ticket.report,
                "Type": ticket.type
            }
            for ticket in tickets
        ]
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Unexpected error in get_data: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

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
        # 1. Update PostgreSQL using SQLAlchemy
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        current_status = ticket.status

        # Only proceed if status is actually changing
        if current_status != new_status:
            # Update status
            ticket.status = new_status
            
            # Create notification
            notification = Notification(message=f"Ticket #{ticket_id} ({ticket.name}) changed from {current_status} to {new_status}")
            db.session.add(notification)
            
            db.session.commit()
            
            # 2. Update Google Sheets
            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
            creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
            client = gspread.authorize(creds)
            sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

            cell = sheet.find(ticket_id)
            if cell:
                headers = sheet.row_values(1)
                if "สถานะ" in headers:
                    status_col = headers.index("สถานะ") + 1
                    sheet.update_cell(cell.row, status_col, new_status)
                    
                    # Prepare payload for LINE notification
                    row_data = sheet.row_values(cell.row)
                    ticket_data = dict(zip(headers, row_data))
                    
                    payload = {
                        'ticket_id': ticket_data.get('Ticket ID'),
                        'user_id': ticket_data.get('User ID'),
                        'status': new_status,
                        'email': ticket_data.get('อีเมล'),
                        'name': ticket_data.get('ชื่อ'),
                        'phone': ticket_data.get('เบอร์ติดต่อ'),
                        'department': ticket_data.get('แผนก'),
                        'created_at': ticket_data.get('วันที่แจ้ง'),
                        'appointment': ticket_data.get('Appointment'),
                        'requested': ticket_data.get('Requeste'),
                        'report': ticket_data.get('Report'),
                        'type': ticket_data.get('Type'),
                        'textbox': ticket_data.get('TEXTBOX'),
                    }

                    notify_user(payload)
                    
                return jsonify({"message": "✅ Updated both PostgreSQL and Google Sheets"})
            return jsonify({"error": "Ticket ID not found in sheet"}), 404
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
        # 1. ลบข้อความที่เกี่ยวข้องก่อน
        Message.query.filter_by(ticket_id=ticket_id).delete()
        
        # 2. ลบ ticket จาก PostgreSQL
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found in database"}), 404
        
        db.session.delete(ticket)
        
        # 3. สร้าง notification
        notification = Notification(message=f"Ticket {ticket_id} has been deleted")
        db.session.add(notification)
        
        db.session.commit()

        # 4. ลบจาก Google Sheets
        try:
            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
            creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
            client = gspread.authorize(creds)
            sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

            cell = sheet.find(ticket_id)
            if cell:
                sheet.delete_rows(cell.row)
                return jsonify({
                    "success": True, 
                    "message": "Ticket deleted from both PostgreSQL and Google Sheets"
                })
            else:
                return jsonify({
                    "success": True,
                    "message": "Ticket deleted from database but not found in Google Sheets"
                }), 200
        except gspread.exceptions.CellNotFound:
            return jsonify({
                "success": True,
                "message": "Ticket deleted from database but not found in Google Sheets"
            }), 200
        except Exception as e:
            print(f"Google Sheets deletion error: {str(e)}")
            return jsonify({
                "success": True,
                "message": f"Ticket deleted from database but Google Sheets error: {str(e)}"
            }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting ticket: {str(e)}")
        return jsonify({
            "error": "Failed to delete ticket",
            "details": str(e)
        }), 500

@app.route('/api/messages/delete', methods=['POST'])
def delete_messages():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    try:
        # ลบข้อความทั้งหมดที่เกี่ยวข้องกับ ticket_id นี้
        Message.query.filter_by(ticket_id=ticket_id).delete()
        db.session.commit()
        return jsonify({"success": True, "message": "Messages deleted successfully"})
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

        # อัปเดต Google Sheets
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

        cell = sheet.find(ticket_id)
        if cell:
            headers = sheet.row_values(1)
            if "TEXTBOX" in headers:
                textbox_col = headers.index("TEXTBOX") + 1
                sheet.update_cell(cell.row, textbox_col, '')

        return jsonify({"success": True, "message": "Textbox cleared automatically"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

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

        # 3. อัปเดต Google Sheets
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

        headers = sheet.row_values(1)
        if "TEXTBOX" in headers:
            textbox_col = headers.index("TEXTBOX") + 1
            
            for ticket in tickets_with_textbox:
                try:
                    cell = sheet.find(ticket.ticket_id)
                    if cell:
                        sheet.update_cell(cell.row, textbox_col, '')
                except gspread.exceptions.CellNotFound:
                    continue

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
        messages = Message.query.filter_by(ticket_id=ticket_id).order_by(Message.timestamp.asc()).all()
        
        result = []
        for message in messages:
            result.append({
                "id": message.id,
                "ticket_id": message.ticket_id,
                "admin_id": message.admin_id,
                "sender_name": message.sender_name,
                "message": message.message,
                "timestamp": message.timestamp.isoformat(),
                "is_read": message.is_read,
                "is_admin_message": message.is_admin_message
            })
        
        # ทำเครื่องหมายว่าข้อความถูกอ่านแล้ว
        if admin_id:
            Message.query.filter(
                Message.ticket_id == ticket_id,
                (Message.admin_id.is_(None) | (Message.admin_id == admin_id)),
                Message.is_read == False
            ).update({"is_read": True})
        else:
            Message.query.filter(
                Message.ticket_id == ticket_id,
                Message.is_read == False
            ).update({"is_read": True})
        
        db.session.commit()
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

    data = request.json
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get("ticket_id")
    new_text = data.get("textbox")
    is_announcement = data.get("is_announcement", False)

    if not ticket_id or new_text is None:
        return jsonify({"error": "ticket_id and text required"}), 400

    # 1. Update PostgreSQL
    try:
        with psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        ) as conn:
            with conn.cursor() as cur:
                # Get current textbox value for comparison
                cur.execute("SELECT textbox, user_id, name FROM tickets WHERE ticket_id = %s", (ticket_id,))
                result = cur.fetchone()
                
                if not result:
                    return jsonify({"error": "Ticket not found"}), 404
                    
                current_text, user_id, name = result
                
                # Only proceed if text is actually changing
                if current_text != new_text:
                    # Update textbox
                    cur.execute("UPDATE tickets SET textbox = %s WHERE ticket_id = %s", (new_text, ticket_id))
                    
                    # Create notification (ไม่สร้าง notification สำหรับประกาศ)
                    if not is_announcement:
                        message = f"New message for ticket {ticket_id} ({name}): {new_text}"
                        cur.execute("INSERT INTO notifications (message) VALUES (%s)", (message,))
                    
                    # Send LINE message if user_id exists
                    if user_id and not is_announcement:
                        send_textbox_message(user_id, new_text)
                        
                    conn.commit()
    except psycopg2.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    # 2. Update Google Sheets
    try:
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

        cell = sheet.find(ticket_id)
        if cell:
            headers = sheet.row_values(1)
            if "TEXTBOX" in headers:
                textbox_col = headers.index("TEXTBOX") + 1
                sheet.update_cell(cell.row, textbox_col, new_text)
            return jsonify({"message": "✅ Updated textbox in PostgreSQL and Google Sheets"})
        return jsonify({"error": "Ticket ID not found in sheet"}), 404
    except gspread.CellNotFound:
        return jsonify({"error": "Ticket ID not found in sheet"}), 404

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
    data = request.json
    announcement_message = data.get('message')

    if not announcement_message:
        return jsonify({"error": "Message is required"}), 400

    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()

        # 1. ดึงรายชื่อผู้ใช้ทั้งหมดที่ต้องการส่งประกาศ
        cur.execute("""
            SELECT ticket_id, user_id, email, name 
            FROM tickets 
            WHERE type = 'Information' 
            AND user_id IS NOT NULL
        """)
        recipients = cur.fetchall()

        recipient_count = 0
        full_message = f"{announcement_message}"

        # 2. อัปเดต TEXTBOX และส่ง LINE Message
        for recipient in recipients:
            ticket_id, user_id, email, name = recipient
            
            # อัปเดต TEXTBOX ใน PostgreSQL
            cur.execute(
                "UPDATE tickets SET textbox = %s WHERE ticket_id = %s",
                (full_message, ticket_id)
            )

            # ส่ง LINE Message
            if user_id:
                send_announcement_message(user_id, full_message, name)
                recipient_count += 1

        # 3. อัปเดต Google Sheets
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

        headers = sheet.row_values(1)
        if "TEXTBOX" in headers:
            textbox_col = headers.index("TEXTBOX") + 1
            # หาแถวทั้งหมดที่ต้องการอัปเดต
            for recipient in recipients:
                ticket_id = recipient[0]
                try:
                    cell = sheet.find(ticket_id)
                    if cell:
                        sheet.update_cell(cell.row, textbox_col, full_message)
                except gspread.exceptions.CellNotFound:
                    continue

        # 4. สร้าง notification ในระบบ
        cur.execute(
            "INSERT INTO notifications (message) VALUES (%s)",
            (f"ประกาศใหม่: {announcement_message}",)
        )

        conn.commit()
        return jsonify({
            "success": True,
            "recipient_count": recipient_count,
            "message": "Announcement sent successfully"
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()




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
    data = request.json
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

@app.route('/update-ticket', methods=['POST', 'OPTIONS'])
def update_ticket():
    if request.method == 'OPTIONS':
        return '', 200  # สำหรับ CORS preflight

    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.json
    ticket_id = data.get("ticket_id")
    new_status = data.get("status")
    new_textbox = data.get("textbox")

    if not ticket_id:
        return jsonify({"error": "ticket_id is required"}), 400

    # --- 1. อัปเดต PostgreSQL ---
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    if new_status is not None:
        cur.execute("UPDATE tickets SET status = %s WHERE ticket_id = %s;", (new_status, ticket_id))
    if new_textbox is not None:
        cur.execute("UPDATE tickets SET textbox = %s WHERE ticket_id = %s;", (new_textbox, ticket_id))
    conn.commit()
    conn.close()

    # --- 2. อัปเดต Google Sheets ---
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
    client = gspread.authorize(creds)
    sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

    try:
        cell = sheet.find(ticket_id)
        headers = sheet.row_values(1)
        if new_status is not None and "สถานะ" in headers:
            status_col = headers.index("สถานะ") + 1
            sheet.update_cell(cell.row, status_col, new_status)
        if new_textbox is not None and "TEXTBOX" in headers:
            textbox_col = headers.index("TEXTBOX") + 1
            sheet.update_cell(cell.row, textbox_col, new_textbox)
    except gspread.exceptions.CellNotFound:
        return jsonify({"error": "Ticket ID not found in sheet"}), 404

    return jsonify({"message": "✅ Ticket updated in PostgreSQL and Google Sheets"})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    ticket_id = request.args.get('ticket_id')
    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    
    # ดึงข้อความทั้งหมดสำหรับ ticket_id นั้นๆ เรียงตามเวลาจากเก่าสุดไปใหม่สุด
    cur.execute("""
        SELECT id, ticket_id, admin_id, sender_name, message, timestamp, is_read, is_admin_message
        FROM messages
        WHERE ticket_id = %s
        ORDER BY timestamp ASC
    """, (ticket_id,))
    
    messages = []
    for row in cur.fetchall():
        messages.append({
            "id": row[0],
            "ticket_id": row[1],
            "admin_id": row[2],
            "sender_name": row[3],
            "message": row[4],
            "timestamp": row[5].isoformat(),
            "is_read": row[6],
            "is_admin_message": row[7]
        })
    
    conn.close()
    return jsonify(messages)

@app.route('/api/messages', methods=['POST'])
def add_message():
    data = request.json
    ticket_id = data.get('ticket_id')
    admin_id = data.get('admin_id')
    sender_name = data.get('sender_name')
    message = data.get('message')
    is_admin_message = data.get('is_admin_message', False)

    if not all([ticket_id, sender_name, message]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    
    try:
        # เพิ่มข้อความใหม่
        cur.execute("""
            INSERT INTO messages (ticket_id, admin_id, sender_name, message, is_admin_message)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, timestamp
        """, (ticket_id, admin_id, sender_name, message, is_admin_message))
        
        new_message = cur.fetchone()
        
        # อัปเดต TEXTBOX ในตาราง tickets เป็นค่าว่างทันที
        cur.execute("""
            UPDATE tickets 
            SET textbox = '' 
            WHERE ticket_id = %s
        """, (ticket_id,))
        
        conn.commit()
        
        # อัปเดต Google Sheets ให้ textbox เป็นค่าว่าง
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
        client = gspread.authorize(creds)
        sheet = client.open(SHEET_NAME).worksheet(WORKSHEET_NAME)

        try:
            cell = sheet.find(ticket_id)
            headers = sheet.row_values(1)
            if "TEXTBOX" in headers:
                textbox_col = headers.index("TEXTBOX") + 1
                sheet.update_cell(cell.row, textbox_col, '')
        except gspread.exceptions.CellNotFound:
            pass  # ไม่ต้องทำอะไรถ้าไม่พบ ticket ใน sheet
        
        return jsonify({
            "id": new_message[0],
            "timestamp": new_message[1].isoformat(),
            "success": True
        })
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/messages/mark-read', methods=['POST'])
def mark_messages_read():
    data = request.json
    ticket_id = data.get('ticket_id')
    admin_id = data.get('admin_id')

    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    
    # ทำเครื่องหมายว่าข้อความถูกอ่านแล้ว
    if admin_id:
        # ถ้ามี admin_id ให้ทำเครื่องหมายเฉพาะข้อความที่ admin นี้ยังไม่ได้อ่าน
        cur.execute("""
            UPDATE messages
            SET is_read = TRUE
            WHERE ticket_id = %s 
            AND (admin_id IS NULL OR admin_id = %s)
            AND is_read = FALSE
        """, (ticket_id, admin_id))
    else:
        # ถ้าไม่มี admin_id ให้ทำเครื่องหมายทุกข้อความ
        cur.execute("""
            UPDATE messages
            SET is_read = TRUE
            WHERE ticket_id = %s
            AND is_read = FALSE
        """, (ticket_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/sync-tickets')
def sync_route():
    try:
        create_tickets_table()
        new_tickets = sync_google_sheet_to_postgres()
        
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT ticket_id, email, name, phone, department, created_at, 
                   status, appointment, requested, report, type, textbox 
            FROM tickets;
        """)
        rows = cur.fetchall()
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
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": "Internal Server Error",
            "message": str(e),
            "status": 500
        }), 500

if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
        sync_google_sheet_to_postgres()
    app.run(host='0.0.0.0', port=5001, debug=False)