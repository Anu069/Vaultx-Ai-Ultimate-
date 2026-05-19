from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models import User, LoginActivity, BreachAlert, AuditLog
from app.services.email_service import generate_otp, send_otp_email, get_otp_expiry
from app.services.audit import log_action, log_login
from app.services.ai_security import analyze_login_threat
import bcrypt
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not all([username, email, password, confirm]):
            flash('All fields are required.', 'error')
            return render_template('auth/register.html')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('auth/register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('auth/register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth/register.html')

        otp = generate_otp()
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            otp_code=otp,
            otp_expires_at=get_otp_expiry(),
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()

        email_sent = send_otp_email(email, otp, 'verification')
        session['pending_verify_user_id'] = user.id

        if email_sent:
            flash('Account created! Check your email for the verification code.', 'success')
        else:
            flash(f'Account created! Email unavailable. Use OTP: {otp}', 'warning')

        return redirect(url_for('auth.verify_email'))

    return render_template('auth/register.html')

@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('pending_verify_user_id')
    if not user_id:
        flash('Session expired. Please register again.', 'error')
        return redirect(url_for('auth.register'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please register again.', 'error')
        return redirect(url_for('auth.register'))

    if user.is_verified:
        session.pop('pending_verify_user_id', None)
        flash('Email already verified. Please log in.', 'info')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        if not user.otp_code or not user.otp_expires_at or user.otp_expires_at < datetime.utcnow():
            flash('OTP has expired. Please request a new one.', 'error')
            return render_template('auth/verify_email.html', email=user.email)

        if otp == user.otp_code:
            user.is_verified = True
            user.otp_code = None
            user.otp_expires_at = None
            db.session.commit()
            session.pop('pending_verify_user_id', None)
            log_action(user.id, 'EMAIL_VERIFIED', 'User verified email address')
            flash('Email verified! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid OTP code. Please try again.', 'error')

    return render_template('auth/verify_email.html', email=user.email)

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    user_id = session.get('pending_verify_user_id') or session.get('pending_2fa_user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Session expired. Please start again.'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    otp = generate_otp()
    user.otp_code = otp
    user.otp_expires_at = get_otp_expiry()
    db.session.commit()

    purpose = 'verification' if not user.is_verified else 'login'
    email_sent = send_otp_email(user.email, otp, purpose)

    if email_sent:
        return jsonify({'success': True, 'message': 'New OTP sent to your email.'})
    else:
        return jsonify({'success': True, 'message': f'OTP: {otp} (email not configured)'})

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')

        if not identifier or not password:
            flash('Please enter your username/email and password.', 'error')
            return render_template('auth/login.html')

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if not user:
            flash('Invalid credentials.', 'error')
            return render_template('auth/login.html')

        if user.is_locked():
            remaining = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1)
            flash(f'Account locked due to too many failed attempts. Try again in {remaining} minute(s).', 'error')
            log_login(user.id, 'blocked', 'high')
            return render_template('auth/login.html')

        if not verify_password(password, user.password_hash):
            user.login_attempts = (user.login_attempts or 0) + 1
            max_attempts = 5

            if user.login_attempts >= max_attempts:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
                flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                log_login(user.id, 'blocked', 'high')
            else:
                remaining_attempts = max_attempts - user.login_attempts
                db.session.commit()
                flash(f'Invalid credentials. {remaining_attempts} attempt(s) remaining.', 'error')
                log_login(user.id, 'failed', 'medium')

            return render_template('auth/login.html')

        if not user.is_verified:
            session['pending_verify_user_id'] = user.id
            flash('Please verify your email before logging in.', 'warning')
            return redirect(url_for('auth.verify_email'))

        # Threat analysis
        threat = analyze_login_threat(ip, ua, user.login_attempts or 0, user.username)

        # Reset login attempts on success
        user.login_attempts = 0
        user.locked_until = None
        db.session.commit()

        # 2FA check
        if user.two_fa_enabled:
            otp = generate_otp()
            user.otp_code = otp
            user.otp_expires_at = get_otp_expiry()
            db.session.commit()
            session['pending_2fa_user_id'] = user.id
            email_sent = send_otp_email(user.email, otp, 'login')
            if not email_sent:
                flash(f'2FA OTP: {otp} (email not configured)', 'warning')
            return redirect(url_for('auth.two_fa'))

        # Direct login
        login_user(user, remember=False)
        user.last_login = datetime.utcnow()
        user.last_activity = datetime.utcnow()
        db.session.commit()

        log_login(user.id, 'success', threat['level'])
        log_action(user.id, 'LOGIN', f'Successful login from {ip}')

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html')

@auth_bp.route('/2fa', methods=['GET', 'POST'])
def two_fa():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        if not user.otp_code or not user.otp_expires_at or user.otp_expires_at < datetime.utcnow():
            flash('OTP expired. Please log in again.', 'error')
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('auth.login'))

        if otp == user.otp_code:
            user.otp_code = None
            user.otp_expires_at = None
            user.last_login = datetime.utcnow()
            user.last_activity = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=False)
            session.pop('pending_2fa_user_id', None)

            log_action(user.id, '2FA_LOGIN', '2FA verified successfully')
            log_login(user.id, 'success', 'none')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid OTP code. Please try again.', 'error')

    return render_template('auth/two_fa.html', email=user.email)

@auth_bp.route('/logout')
@login_required
def logout():
    log_action(current_user.id, 'LOGOUT', 'User logged out')
    logout_user()
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/settings/2fa', methods=['GET', 'POST'])
@login_required
def toggle_2fa():
    if request.method == 'POST':
        data = request.get_json() or {}
        enabled = data.get('enabled', False)
        if not isinstance(enabled, bool):
            enabled = str(enabled).lower() == 'true'
        current_user.two_fa_enabled = enabled
        db.session.commit()
        status = 'enabled' if enabled else 'disabled'
        log_action(current_user.id, f'2FA_{status.upper()}', f'Two-factor authentication {status}')
        return jsonify({'success': True, 'enabled': enabled})
    return jsonify({'enabled': current_user.two_fa_enabled})

@auth_bp.route('/activity')
@login_required
def activity():
    logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.created_at.desc()).limit(50).all()
    logins = LoginActivity.query.filter_by(user_id=current_user.id)\
        .order_by(LoginActivity.created_at.desc()).limit(20).all()
    return render_template('auth/activity.html', logs=logs, logins=logins)
