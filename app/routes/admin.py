from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import User, AuditLog, LoginActivity, BreachAlert
from app import db
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        # First user is admin
        if current_user.id != 1:
            flash('Access denied.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated

@admin_bp.route('/')
@login_required
@admin_required
def index():
    users = User.query.order_by(User.created_at.desc()).all()
    total_logs = AuditLog.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template('admin/index.html', users=users, total_logs=total_logs, recent_logs=recent_logs)

@admin_bp.route('/send-alert/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def send_alert(user_id):
    from flask import request
    message = request.form.get('message', '')
    severity = request.form.get('severity', 'medium')
    if message:
        alert = BreachAlert(
            user_id=user_id,
            alert_type='admin_alert',
            message=message,
            severity=severity
        )
        db.session.add(alert)
        db.session.commit()
    return redirect(url_for('admin.index'))
