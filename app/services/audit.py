from app import db
from app.models import AuditLog, LoginActivity
from flask import request
from datetime import datetime

def log_action(user_id: int, action: str, details: str = None, risk_level: str = 'low'):
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent', '')[:500] if request else None,
            risk_level=risk_level,
            created_at=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

def log_login(user_id: int, status: str, threat_level: str = 'none'):
    try:
        activity = LoginActivity(
            user_id=user_id,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent', '')[:500] if request else None,
            status=status,
            threat_level=threat_level,
            created_at=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
