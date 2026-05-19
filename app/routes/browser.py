from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.services.audit import log_action
from datetime import datetime

browser_bp = Blueprint('browser', __name__)

@browser_bp.route('/')
@login_required
def index():
    log_action(current_user.id, 'PRIVATE_BROWSER_OPENED', 'Private browser session started')
    # 'now' is injected globally via context_processor, no need to pass manually
    return render_template('browser/index.html')

@browser_bp.route('/clear-session', methods=['POST'])
@login_required
def clear_session():
    log_action(current_user.id, 'BROWSER_SESSION_CLEARED', 'Private browser session wiped')
    return jsonify({'success': True, 'message': 'Browser session cleared'})
