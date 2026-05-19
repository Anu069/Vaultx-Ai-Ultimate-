from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.services.ai_security import (
    get_ai_security_advice, detect_phishing_url,
    calculate_password_strength, calculate_vault_health
)
from app.models import PasswordEntry, SecureNote, SecureFile
from app.services.audit import log_action

ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/')
@login_required
def index():
    return render_template('ai/index.html')

@ai_bp.route('/advisor', methods=['POST'])
@login_required
def advisor():
    data = request.get_json() or {}
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({'error': 'No query provided'}), 400
    
    if len(query) > 500:
        return jsonify({'error': 'Query too long'}), 400
    
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    notes = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    files = SecureFile.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    health = calculate_vault_health(passwords, notes, files)
    
    context = {
        'vault_score': health['score'],
        'total_passwords': health['details'].get('total', 0),
        'weak_passwords': health['details'].get('weak', 0),
        'reused_passwords': health['details'].get('reused', 0),
        '2fa_enabled': current_user.two_fa_enabled
    }
    
    advice = get_ai_security_advice(query, context)
    log_action(current_user.id, 'AI_ADVISOR_QUERY', f'Query: {query[:100]}')
    
    return jsonify({'advice': advice, 'markdown': True})

@ai_bp.route('/phishing-check', methods=['POST'])
@login_required
def phishing_check():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    result = detect_phishing_url(url)
    log_action(current_user.id, 'PHISHING_CHECK', f'Checked URL: {url[:100]}', 
               'medium' if result['risk'] in ['high', 'medium'] else 'low')
    
    return jsonify(result)

@ai_bp.route('/password-risk', methods=['POST'])
@login_required
def password_risk():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = calculate_password_strength(password)
    return jsonify(result)

@ai_bp.route('/vault-health')
@login_required
def vault_health():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    notes = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    files = SecureFile.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    health = calculate_vault_health(passwords, notes, files)
    return jsonify(health)

@ai_bp.route('/recommendations')
@login_required
def recommendations():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    notes = SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    files = SecureFile.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    health = calculate_vault_health(passwords, notes, files)
    
    recs = health.get('recommendations', [])
    
    if not current_user.two_fa_enabled:
        recs.insert(0, 'Enable Two-Factor Authentication (2FA) for your account')
    
    if not recs:
        recs = ['Your vault looks secure! Keep up the good security habits.']
    
    return jsonify({'recommendations': recs, 'health': health})
