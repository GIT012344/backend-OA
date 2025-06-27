import eventlet
eventlet.monkey_patch()
from flask import Flask, jsonify, request
import requests
from flask_cors import CORS 
import psycopg2
from datetime import datetime
import os
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
import traceback


LINE_ACCESS_TOKEN = "0C9ZwOVQ7BOY9dLLfvEqAP+RhpIXmlpcuHf4fgJ184c0nvKzc5S+rKAyjh7yDqadGK1VNxe36n+nswrYaDSLCKOGmhuXjrsRgspH1RF4hGWdgOrrMlBhGnYQjxB9jHDSXVHO5HYkjLJdWOarG8PXKQdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
socketio = SocketIO(app, cors_allowed_origins="*")

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
    try:
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
                }
            ]
        }

        # ส่งข้อความไปยัง LINE Messaging API
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            print(f"[send_textbox_message] LINE API Error: {response.status_code} - {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"[send_textbox_message] Exception: {e}")
        print(traceback.format_exc())
        return False

def notify_user(payload):
    try:
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
        if response.status_code != 200:
            print(f"[notify_user] LINE API Error: {response.status_code} - {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"[notify_user] Exception: {e}")
        print(traceback.format_exc())
        return False



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

def safe_isoformat(dt):
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except Exception:
            return dt  # ถ้าแปลงไม่ได้ ส่ง string กลับไปเลย
    if isinstance(dt, datetime):
        return dt.isoformat()
    return None

@app.route('/api/upcoming-appointments')
def get_upcoming_appointments():
    try:
        # ดึง Ticket ทั้งหมดที่มีการนัดหมาย เรียงตามเวลานัดหมายจากใกล้ถึงไปไกล
        tickets_with_appointment = Ticket.query.filter(
            Ticket.appointment.isnot(None)
        ).order_by(Ticket.appointment.asc()).limit(5).all()
        
        result = []
        for ticket in tickets_with_appointment:
            # แปลงวันที่เป็นรูปแบบไทย
            appointment_date = ticket.appointment
            thai_months = [
                'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน',
                'พฤษภาคม', 'มิถุนายน', 'กรกฎาคม', 'สิงหาคม',
                'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม'
            ]
            thai_weekdays = [
                'วันอาทิตย์', 'วันจันทร์', 'วันอังคาร', 'วันพุธ',
                'วันพฤหัสบดี', 'วันศุกร์', 'วันเสาร์'
            ]
            
            weekday = thai_weekdays[appointment_date.weekday()]
            day = appointment_date.day
            month = thai_months[appointment_date.month - 1]
            year = appointment_date.year + 543  # แปลงเป็น พ.ศ.
            time = appointment_date.strftime('%H:%M')
            
            thai_date = f"{weekday}ที่ {day} {month} พ.ศ. {year} เวลา {time}"
            
            result.append({
                "ticket_id": ticket.ticket_id,
                "name": ticket.name,
                "appointment": thai_date,
                "department": ticket.department,
                "status": ticket.status,
                "type": ticket.type,
                "raw_appointment": safe_isoformat(appointment_date)
            })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/notifications')
def get_notifications():
    # Get last 20 notifications, newest first using SQLAlchemy
    notifications = Notification.query.order_by(Notification.timestamp.desc()).limit(20).all()
    
    result = []
    for notification in notifications:
        result.append({
            "id": notification.id,
            "message": notification.message,
            "timestamp": safe_isoformat(notification.timestamp),
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
    if not date_str or str(date_str).lower() == 'none':
        return None
    try:
        s = str(date_str).strip()
        # ถ้าเจอช่วงเวลา 09:00-10:00 เอา 09:00 (หรือแยกเอาเฉพาะเวลาที่ต้องการ)
        if '-' in s and not s.startswith('-'):
            date_part, time_part = s.split(' ', 1) if ' ' in s else (s, '')
            if '-' in time_part:
                time_part = time_part.split('-')[0].strip()
            s = f"{date_part} {time_part}".strip()
        # ลอง format ต่างๆ
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%d',
            '%d/%m/%Y %H:%M',
            '%d/%m/%Y',
            '%Y/%m/%d %H:%M',
            '%d-%m-%Y %H:%M',
        ]
        for fmt in formats:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None
    except Exception:
        return None
    try:
        # รองรับทั้งเคส 26/06/2025 09:00-10:00
        if '-' in str(date_str):
            date_part, _ = str(date_str).split('-', 1)
            date_str = date_part.strip()
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%d/%m/%Y %H:%M',
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%dT%H:%M:%S',
        ]
        for fmt in formats:
            try:
                return datetime.strptime(str(date_str), fmt)
            except ValueError:
                continue
        return None
    except Exception:
        return None

@app.route('/api/data')
#   #@cache.cached(timeout=60) 
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
                "วันที่แจ้ง": safe_isoformat(ticket.created_at) if ticket.created_at else "-",
                "สถานะ": ticket.status if ticket.status else "-",
                "Appointment": safe_isoformat(ticket.appointment) if ticket.appointment else None,
                "Requeste": ticket.requested if ticket.requested else "-",
                "Report": ticket.report if ticket.report else "-",
                "Type": ticket.type if ticket.type else "-"
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

@app.route('/api/latest-service-appointments')
def get_latest_service_appointments():
    try:
        # ดึง Ticket ประเภท Service ที่มีการนัดหมาย เรียงตามเวลานัดหมายจากใกล้ถึงไปไกล
        service_tickets = Ticket.query.filter(
            Ticket.type == 'Service',
            Ticket.appointment.isnot(None)
        ).order_by(Ticket.appointment.asc()).limit(5).all()
        
        result = []
        for ticket in service_tickets:
            result.append({
                "ticket_id": ticket.ticket_id,
                "name": ticket.name,
                "appointment": ticket.appointment.strftime('%A, %d %B %Y %H:%M') if ticket.appointment else "-",
                "department": ticket.department,
                "status": ticket.status
            })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500        

@app.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    print(f"[update-status] data: {data}")
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    ticket_id = data.get("ticket_id")
    new_status = data.get("status")
    print(f"[update-status] ticket_id: {ticket_id}")
    if not ticket_id or not new_status:
        return jsonify({"error": "ticket_id and status required"}), 400
    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            print(f"[update-status] Ticket not found: {ticket_id}")
            return jsonify({"error": "Ticket not found"}), 404
            
        current_status = ticket.status

        # Only proceed if status is actually changing
        if current_status != new_status:
            # Update status
            ticket.status = new_status
            
            # Create notification
            notification = Notification(
                message=f"Ticket #{ticket_id} ({ticket.name}) changed from {current_status} to {new_status}"
            )
            db.session.add(notification)
            db.session.commit()

            # เตรียม payload สำหรับ notify_user
            try:
                if ticket.appointment:
                    if isinstance(ticket.appointment, str):
                        # พยายาม parse string เป็น datetime ก่อน
                        try:
                            dt = datetime.fromisoformat(ticket.appointment)
                            appointment_str = dt.isoformat()
                        except Exception:
                            appointment_str = ticket.appointment  # ถ้า parse ไม่ได้ ส่ง string เดิม
                    else:
                        appointment_str = ticket.appointment.isoformat()
                else:
                    appointment_str = None
            except Exception as e:
                print(f"[update-status] appointment error: {e}")
                appointment_str = None

            payload = {
                'user_id': ticket.user_id,
                'ticket_id': ticket.ticket_id,
                'name': ticket.name,
                'phone': ticket.phone,
                'department': ticket.department,
                'status': ticket.status,
                'appointment': appointment_str,
                'type': ticket.type,
                'report': ticket.report
            }
            if ticket.user_id:
                try:
                    notify_user(payload)
                except Exception as e:
                    print(f"[update-status] notify_user error: {e}")
            # emit event ticket_updated
            socketio.emit('ticket_updated', payload)
            print('>>> emit ticket_updated', payload)
            socketio.emit('refresh_data')
            print('>>> emit refresh_data')
            return jsonify({"message": "✅ Updated PostgreSQL"})
        else:
            print('[update-status] Status unchanged')
            return jsonify({"message": "Status unchanged"})
            
    except Exception as e:
        db.session.rollback()
        print(f"[update-status] Exception: {e}")
        print(traceback.format_exc())
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
        ticket = Ticket.query.filter_by(ticket_id=ticket_id).first()
        if not ticket:
            return jsonify({"error": "Ticket not found in database"}), 404
        
        db.session.delete(ticket)
        
        # 3. สร้าง notification
        notification = Notification(message=f"Ticket {ticket_id} has been deleted")
        db.session.add(notification)
        
        db.session.commit()
        # emit event ticket_deleted
        socketio.emit('ticket_deleted', {'ticket_id': ticket_id})
        print('>>> emit ticket_deleted', {'ticket_id': ticket_id})
        socketio.emit('refresh_data')
        print('>>> emit refresh_data')
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
        socketio.emit('refresh_data')
        print('>>> emit refresh_data (delete-messages)')
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
        socketio.emit('refresh_data')
        print('>>> emit refresh_data (auto-clear-textbox)')
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
        socketio.emit('refresh_data')
        print('>>> emit refresh_data (clear-textboxes)')
        return jsonify({
            "success": True,
            "cleared_count": len(tickets_with_textbox),
            "message": f"Cleared {len(tickets_with_textbox)} textboxes"
        })
    except Exception as e:
        db.session.rollback()
        print(f"clear_textboxes error: {e}")
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
                "timestamp": safe_isoformat(message.timestamp),
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
        socketio.emit('refresh_data')
        print('>>> emit refresh_data')
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
    socketio.emit('refresh_data')
    print('>>> emit refresh_data')
    return jsonify({"message": "✅ Updated textbox in PostgreSQL"})

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

        # 4. สร้าง notification ในระบบ
        cur.execute(
            "INSERT INTO notifications (message) VALUES (%s)",
            (f"ประกาศใหม่: {announcement_message}",)
        )

        conn.commit()
        socketio.emit('refresh_data')
        print('>>> emit refresh_data')
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
    try:
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

        response = requests.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            print(f"[send_announcement_message] LINE API Error: {response.status_code} - {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"[send_announcement_message] Exception: {e}")
        print(traceback.format_exc())
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
                "วันที่แจ้ง": safe_isoformat(row[5]) if row[5] else "",
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

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
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
    # emit event ticket_updated
    socketio.emit('ticket_updated', {'ticket_id': ticket_id, 'status': new_status, 'textbox': new_textbox})
    print('>>> emit ticket_updated', {'ticket_id': ticket_id, 'status': new_status, 'textbox': new_textbox})
    socketio.emit('refresh_data')
    print('>>> emit refresh_data')
    return jsonify({"message": "✅ Ticket updated in PostgreSQL"})

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
            "timestamp": safe_isoformat(row[5]),
            "is_read": row[6],
            "is_admin_message": row[7]
        })
    
    conn.close()
    return jsonify(messages)

@app.route('/api/messages', methods=['POST'])
def add_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    ticket_id = data.get('ticket_id')
    admin_id = data.get('admin_id')
    sender_name = data.get('sender_name')
    message = data.get('message')
    is_admin_message = data.get('is_admin_message', False)
    user_id = data.get('user_id')
    line_id = data.get('line_id')
    platform = data.get('platform')

    if not all([ticket_id, sender_name, message]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    try:
        # เพิ่มข้อความใหม่
        cur.execute("""
            INSERT INTO messages (ticket_id, admin_id, sender_name, message, is_admin_message, user_id, line_id, platform)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, timestamp
        """, (ticket_id, admin_id, sender_name, message, is_admin_message, user_id, line_id, platform))
        new_message = cur.fetchone()
        if not new_message:
            conn.rollback()
            return jsonify({"error": "Failed to insert message"}), 500
        conn.commit()
        # emit event ticket_added
        socketio.emit('ticket_added', {'ticket_id': ticket_id, 'admin_id': admin_id, 'sender_name': sender_name, 'message': message, 'is_admin_message': is_admin_message})
        print('>>> emit ticket_added', {'ticket_id': ticket_id, 'admin_id': admin_id, 'sender_name': sender_name, 'message': message, 'is_admin_message': is_admin_message})
        socketio.emit('refresh_data')
        print('>>> emit refresh_data')
        socketio.emit('new_message', {
            'ticket_id': ticket_id,
            'admin_id': admin_id,
            'sender_name': sender_name,
            'message': message,
            'is_admin_message': is_admin_message
        })
        print('>>> emit new_message', {
            'ticket_id': ticket_id,
            'admin_id': admin_id,
            'sender_name': sender_name,
            'message': message,
            'is_admin_message': is_admin_message
        })
        # (A) ถ้าเป็นข้อความจากแอดมิน ให้ยิง LINE API
        if is_admin_message:
            # ถ้า user_id ไม่ได้ส่งมา ให้ query จาก ticket_id
            if not user_id:
                cur.execute("SELECT user_id FROM tickets WHERE ticket_id = %s", (ticket_id,))
                row = cur.fetchone()
                user_id = row[0] if row else None
            if user_id:
                print(f"[add_message] send_textbox_message to LINE user_id={user_id}")
                send_textbox_message(user_id, message)
            else:
                print(f"[add_message] No user_id found for ticket_id={ticket_id}, not sending to LINE")
        return jsonify({
            "id": new_message[0],
            "timestamp": safe_isoformat(new_message[1]),
            "success": True
        })
    except Exception as e:
        conn.rollback()
        print(f"[add_message] Exception: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# (B) เพิ่ม webhook สำหรับ LINE
@app.route('/webhook/line', methods=['POST'])
def webhook_line():
    try:
        data = request.get_json()
        print(f"[webhook_line] data: {data}")
        events = data.get('events', [])
        for event in events:
            if event.get('type') == 'message' and event['message'].get('type') == 'text':
                user_id = event['source'].get('userId')
                message_text = event['message'].get('text')
                # หา ticket_id ล่าสุดของ user_id นี้ (หรือ logic mapping ตามที่เหมาะสม)
                ticket_id = None
                with psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT ticket_id FROM tickets WHERE user_id = %s ORDER BY created_at DESC LIMIT 1", (user_id,))
                        row = cur.fetchone()
                        if row:
                            ticket_id = row[0]
                if not ticket_id:
                    print(f"[webhook_line] No ticket_id found for user_id={user_id}")
                    continue
                # insert message ลง db
                with psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT) as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO messages (ticket_id, sender_name, message, is_admin_message, user_id, platform)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (ticket_id, 'LINE User', message_text, False, user_id, 'LINE'))
                        conn.commit()
                # emit event new_message กลับหา frontend
                socketio.emit('new_message', {
                    'ticket_id': ticket_id,
                    'admin_id': None,
                    'sender_name': 'LINE User',
                    'message': message_text,
                    'is_admin_message': False
                })
                print(f"[webhook_line] emit new_message for ticket_id={ticket_id}")
        return jsonify({'success': True})
    except Exception as e:
        print(f"[webhook_line] Exception: {e}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages/mark-read', methods=['POST'])
def mark_messages_read():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
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
        return jsonify({"message": "Sync route called but no Google Sheets sync logic implemented"})
    except Exception as e:
        return jsonify({
            "error": "Internal Server Error",
            "message": str(e),
            "status": 500
        }), 500

if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
    print(app.url_map)
    socketio.run(app, host='0.0.0.0', port=5004, debug=False)