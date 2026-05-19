from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address)

def create_app(config_name=None):
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    from config import config
    env = config_name or os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config.get(env, config['default']))

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access VaultX.'
    login_manager.login_message_category = 'info'

    # ── CONTEXT PROCESSOR: inject unread_alerts into every template ──
    @app.context_processor
    def inject_globals():
        unread_alerts = 0
        if current_user.is_authenticated:
            try:
                from app.models import BreachAlert
                unread_alerts = BreachAlert.query.filter_by(
                    user_id=current_user.id, is_read=False
                ).count()
            except Exception:
                pass
        from datetime import datetime
        return dict(unread_alerts=unread_alerts, now=datetime.utcnow())

    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.vault import vault_bp
    from app.routes.ai_security import ai_bp
    from app.routes.browser import browser_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(vault_bp, url_prefix='/vault')
    app.register_blueprint(ai_bp, url_prefix='/ai')
    app.register_blueprint(browser_bp, url_prefix='/browser')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')

    with app.app_context():
        db.create_all()

    return app
