from flask import Blueprint, render_template, redirect, url_for, request, jsonify, session
from flask_login import login_required, current_user
from app import db
from app.models import PasswordEntry, SecureNote, SecureFile, AuditLog, LoginActivity, BreachAlert
from app.services.ai_security import calculate_vault_health
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

def update_activity():
    current_user.last_activity = datetime.utcnow()
    db.session.commit()

@dashboard_bp.route('/')
@login_required
def index():
    update_activity()

    passwords = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    notes = SecureNote.query.filter_by(user_id=current_user.id).all()
    files = SecureFile.query.filter_by(user_id=current_user.id).all()

    health = calculate_vault_health(passwords, notes, files)

    active_passwords = [p for p in passwords if not p.is_deleted]
    weak_passwords = [p for p in active_passwords if p.strength_score < 40]
    expiring_soon = [p for p in active_passwords if p.expires_soon() and not p.is_expired()]
    expired = [p for p in active_passwords if p.is_expired()]

    recent_logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.created_at.desc()).limit(10).all()
    recent_logins = LoginActivity.query.filter_by(user_id=current_user.id)\
        .order_by(LoginActivity.created_at.desc()).limit(5).all()

    alerts = BreachAlert.query.filter_by(user_id=current_user.id)\
        .order_by(BreachAlert.created_at.desc()).limit(5).all()

    categories = {}
    for p in active_passwords:
        cat = p.category or 'General'
        categories[cat] = categories.get(cat, 0) + 1

    timeline = []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        count = LoginActivity.query.filter(
            LoginActivity.user_id == current_user.id,
            LoginActivity.created_at >= day.replace(hour=0, minute=0, second=0),
            LoginActivity.created_at <= day.replace(hour=23, minute=59, second=59)
        ).count()
        timeline.append({'day': day.strftime('%b %d'), 'count': count})

    return render_template('dashboard/index.html',
        health=health,
        total_passwords=len(active_passwords),
        weak_count=len(weak_passwords),
        expiring_soon=expiring_soon,
        expired_count=len(expired),
        total_notes=len([n for n in notes if not n.is_deleted]),
        total_files=len([f for f in files if not f.is_deleted]),
        recent_logs=recent_logs,
        recent_logins=recent_logins,
        alerts=alerts,
        categories=categories,
        login_timeline=timeline
    )

@dashboard_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_theme':
            current_user.theme = request.form.get('theme', 'dark-cyber')
            db.session.commit()
            return jsonify({'success': True})

        elif action == 'update_preferences':
            current_user.sound_enabled = request.form.get('sound_enabled') == 'true'
            current_user.cursor_style = request.form.get('cursor_style', 'default')
            current_user.animation_level = request.form.get('animation_level', 'full')
            current_user.layout = request.form.get('layout', 'default')
            db.session.commit()
            return jsonify({'success': True})

        elif action == 'save_custom_theme':
            import json
            theme_data = {
                'primary': request.form.get('primary_color', '#00ff9f'),
                'secondary': request.form.get('secondary_color', '#0066ff'),
                'background': request.form.get('bg_color', '#0a0a0f'),
                'surface': request.form.get('surface_color', '#12121f'),
                'text': request.form.get('text_color', '#e0e0e0')
            }
            current_user.custom_theme = json.dumps(theme_data)
            current_user.theme = 'custom'
            db.session.commit()
            return jsonify({'success': True})

        elif action == 'toggle_stealth':
            current_user.stealth_mode = not current_user.stealth_mode
            db.session.commit()
            return jsonify({'success': True, 'stealth': current_user.stealth_mode})

        elif action == 'toggle_honey':
            current_user.honey_vault_enabled = not current_user.honey_vault_enabled
            db.session.commit()
            return jsonify({'success': True, 'honey': current_user.honey_vault_enabled})

        elif action == 'set_panic_password':
            from app.routes.auth import hash_password
            panic_pw = request.form.get('panic_password', '')
            if panic_pw:
                current_user.panic_password = hash_password(panic_pw)
                db.session.commit()
                return jsonify({'success': True})

        return jsonify({'success': False, 'message': 'Unknown action'}), 400

    return render_template('dashboard/settings.html')

@dashboard_bp.route('/panic', methods=['POST'])
@login_required
def panic_mode():
    from flask_login import logout_user
    from app.services.audit import log_action
    log_action(current_user.id, 'PANIC_MODE', 'Panic mode activated', 'high')
    logout_user()
    session.clear()
    return jsonify({'success': True, 'redirect': url_for('auth.login')})

@dashboard_bp.route('/session-check')
@login_required
def session_check():
    timeout = current_user.last_activity + timedelta(minutes=30)
    if datetime.utcnow() > timeout:
        from flask_login import logout_user
        logout_user()
        return jsonify({'active': False})
    remaining = int((timeout - datetime.utcnow()).total_seconds())
    current_user.last_activity = datetime.utcnow()
    db.session.commit()
    return jsonify({'active': True, 'remaining': remaining})

@dashboard_bp.route('/alerts/read/<int:alert_id>', methods=['POST'])
@login_required
def read_alert(alert_id):
    alert = BreachAlert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    alert.is_read = True
    db.session.commit()
    return jsonify({'success': True})
