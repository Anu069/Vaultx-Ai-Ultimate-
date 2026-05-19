from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app import db
from app.models import PasswordEntry, SecureNote, BreachAlert
from datetime import datetime

api_bp = Blueprint('api', __name__)

@api_bp.route('/stats')
@login_required
def stats():
    passwords = PasswordEntry.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    weak = sum(1 for p in passwords if p.strength_score < 40)
    strong = sum(1 for p in passwords if p.strength_score >= 70)
    expired = sum(1 for p in passwords if p.is_expired())
    fav = sum(1 for p in passwords if p.is_favourite)
    unread_alerts = BreachAlert.query.filter_by(user_id=current_user.id, is_read=False).count()

    return jsonify({
        'total_passwords': len(passwords),
        'weak': weak,
        'strong': strong,
        'expired': expired,
        'favourites': fav,
        'notes': SecureNote.query.filter_by(user_id=current_user.id, is_deleted=False).count(),
        'unread_alerts': unread_alerts
    })

@api_bp.route('/ping')
@login_required
def ping():
    current_user.last_activity = datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'ok'})

@api_bp.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return jsonify({'results': []})

    passwords = PasswordEntry.query.filter(
        PasswordEntry.user_id == current_user.id,
        PasswordEntry.is_deleted == False,
        PasswordEntry.title.ilike(f'%{q}%')
    ).limit(10).all()

    notes = SecureNote.query.filter(
        SecureNote.user_id == current_user.id,
        SecureNote.is_deleted == False,
        SecureNote.title.ilike(f'%{q}%')
    ).limit(5).all()

    results = []
    for p in passwords:
        results.append({
            'type': 'password',
            'id': p.id,
            'title': p.title,
            'category': p.category or 'General',
            'url': '/vault/passwords'
        })
    for n in notes:
        results.append({
            'type': 'note',
            'id': n.id,
            'title': n.title,
            'category': n.category or 'General',
            'url': '/vault/notes'
        })

    return jsonify({'results': results})
