from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import os

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config.from_object('config.Config')
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    
    # Security headers with Talisman
    csp = {
        'default-src': ['\'self\''],
        'style-src': ['\'self\'', 'https://cdnjs.cloudflare.com'],
        'script-src': ['\'self\''],
        'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com']
    }
    
    Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
        force_https=True,
        session_cookie_secure=True,
        session_cookie_http_only=True
    )
    
    # Register blueprints
    from app.auth import auth_bp
    from app.routes import main_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    return app
