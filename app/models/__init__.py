from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime, timedelta
import json

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    two_fa_enabled = db.Column(db.Boolean, default=False)
    two_fa_secret = db.Column(db.String(32))
    otp_code = db.Column(db.String(6))
    otp_expires_at = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    theme = db.Column(db.String(50), default='dark-cyber')
    custom_theme = db.Column(db.Text)
    layout = db.Column(db.String(50), default='default')
    sound_enabled = db.Column(db.Boolean, default=True)
    cursor_style = db.Column(db.String(50), default='default')
    animation_level = db.Column(db.String(20), default='full')
    stealth_mode = db.Column(db.Boolean, default=False)
    honey_vault_enabled = db.Column(db.Boolean, default=False)
    panic_password = db.Column(db.String(255))
    
    passwords = db.relationship('PasswordEntry', backref='user', lazy=True, cascade='all, delete-orphan')
    notes = db.relationship('SecureNote', backref='user', lazy=True, cascade='all, delete-orphan')
    files = db.relationship('SecureFile', backref='user', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True, cascade='all, delete-orphan')
    login_activities = db.relationship('LoginActivity', backref='user', lazy=True, cascade='all, delete-orphan')

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def get_custom_theme(self):
        if self.custom_theme:
            try:
                return json.loads(self.custom_theme)
            except:
                return {}
        return {}

class PasswordEntry(db.Model):
    __tablename__ = 'password_entries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200))
    password_encrypted = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    category = db.Column(db.String(100), default='General')
    strength_score = db.Column(db.Integer, default=0)
    is_favourite = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    last_used = db.Column(db.DateTime)
    tags = db.Column(db.String(500))

    def is_expired(self):
        if self.expires_at and self.expires_at < datetime.utcnow():
            return True
        return False

    def expires_soon(self):
        if self.expires_at:
            return self.expires_at < datetime.utcnow() + timedelta(days=7)
        return False

class SecureNote(db.Model):
    __tablename__ = 'secure_notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), default='General')
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    is_pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SecureFile(db.Model):
    __tablename__ = 'secure_files'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_name = db.Column(db.String(300), nullable=False)
    stored_name = db.Column(db.String(300), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    category = db.Column(db.String(100), default='General')
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    risk_level = db.Column(db.String(20), default='low')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginActivity(db.Model):
    __tablename__ = 'login_activities'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    location = db.Column(db.String(200))
    status = db.Column(db.String(20))  # success, failed, blocked
    threat_level = db.Column(db.String(20), default='none')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BreachAlert(db.Model):
    __tablename__ = 'breach_alerts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    alert_type = db.Column(db.String(100))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String(20), default='medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
