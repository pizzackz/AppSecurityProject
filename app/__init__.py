import os
import base64
import stripe
import logging

from dotenv import load_dotenv
from flask import Flask, Response, request, g
# from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import Config

# Load environment variables from .env file
load_dotenv('../.env')

# Main file to define a function to create a flask application instance
# Used to "combine" all important blueprints & configurations together in order to run flask app
# Initialise CSRF protection, SQLAlchemy, Flask-Login, Rate Limiter
csrf: CSRFProtect = CSRFProtect()
db: SQLAlchemy = SQLAlchemy()
# login_manager: LoginManager = LoginManager()
limiter = Limiter(
        key_func=get_remote_address,
        default_limits=Config.RATELIMIT_DEFAULT,
        storage_uri=Config.RATELIMIT_STORAGE_URL
)

# Generate nonce (number used once), randomly generated base64-encoded string
# to be used with CSP to only allow scripts & styles with correct nonce to be
# executed on client-side
def generate_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")


def create_app() -> Flask:
    app: Flask = Flask(__name__)  # Create Flask application instance
    app.config.from_object(Config)  # Load configuration from Config class in 'config.py'

    # Set Content Security Policy header to mitigate XSS attacks
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        nonce = g.get('nonce')
        if nonce:
            csp_directives = app.config['CSP_DIRECTIVES'].copy()
            csp_directives['style-src'].append(f"'nonce-{nonce}'")
            csp_directives['script-src'].append(f"'nonce-{nonce}'")
            csp_header_value = "; ".join([f"{key} {' '.join(value)}" for key, value in csp_directives.items()])
            response.headers['Content-Security-Policy'] = csp_header_value
        return response

    @app.context_processor
    def inject_nonce():
        return dict(nonce=g.get('nonce'))

    # Register blueprints
    from app.blueprints.admin.admin_recipe_bp import admin_recipe_bp
    from app.blueprints.member.member_subscription_bp import member_subscription_bp

    app.register_blueprint(admin_recipe_bp)
    app.register_blueprint(member_subscription_bp)


    # Enable CSRF protection, SQLAlchemy, Flask-Login, Rate Limiting &  for app
    csrf.init_app(app)
    db.init_app(app)
    # login_manager.init_app(app)
    limiter.init_app(app)

    # Return Flask app instance
    return app
