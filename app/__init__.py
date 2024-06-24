import logging

from logging import Logger, StreamHandler, Formatter
from dotenv import load_dotenv
from flask import Flask, Response, g
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_session import Session

from app.config import Config
from app.utils import generate_nonce, register_commands


# Load environment variables from .env file
load_dotenv()

# Main file to define a function to create a flask application instance
# Used to "combine" all important blueprints & configurations together in order to run flask app
# Initialise CSRF protection, SQLAlchemy, LoginManager, Rate Limiter
csrf: CSRFProtect = CSRFProtect()
db: SQLAlchemy = SQLAlchemy()
login_manager: LoginManager = LoginManager()
limiter = Limiter(key_func=get_remote_address, default_limits=Config.RATELIMIT_DEFAULT, storage_uri=Config.RATELIMIT_STORAGE_URL)


# Setup logger for own logs function
def setup_custom_logger(name: str) -> Logger:
    """Configure a custom logger for the application"""
    logger: Logger = logging.getLogger(name)

    # Remove all handlers associated with logger
    if logger.hasHandlers():
        print("ran")
        logger.handlers.clear()

    handler: StreamHandler = logging.StreamHandler()
    formatter: Formatter = logging.Formatter(
        "%(levelname)s:%(name)s - - [%(asctime)s] \"%(message)s\"", 
        datefmt="%d/%b/%Y %H:%M:%S"
    )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevents log messages from being propagated to Flask default logger

    return logger


def create_app() -> Flask:
    app: Flask = Flask(__name__)  # Create Flask application instance
    app.config.from_object(Config)  # Load configuration from Config class in 'config.py'

    # Initialise extensions
    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    
    # Custom logger for app logic
    custom_logger: Logger = setup_custom_logger("tastefully")
    app.config["CUSTOM_LOGGER"] = custom_logger

    # Configure Flask-Session to use SQLAlchemy
    app.config["SESSION_SQLALCHEMY"] = db
    Session(app)

    # Set up user loader to load user by querying database for 'User' entity
    @login_manager.user_loader
    def load_user(user_id: int) -> User:
        return User.query.get(int(user_id))

    # Set Content Security Policy header to mitigate XSS attacks
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        nonce = g.get("nonce")
        if nonce:
            csp_directives = app.config["CSP_DIRECTIVES"].copy()
            csp_directives["style-src"].append(f"'nonce-{nonce}'")
            csp_directives["script-src"].append(f"'nonce-{nonce}'")
            csp_directives["script-src-attr"].append(f"'nonce-{nonce}'")
            csp_header_value = "; ".join(
                [f"{key} {' '.join(value)}" for key, value in csp_directives.items()]
            )
            response.headers["Content-Security-Policy"] = csp_header_value

        # Set additional secure headers
        for key, value in app.config["SECURE_HEADERS"].items():
            response.headers[key] = value

        return response

    @app.before_request
    def set_none():
        g.nonce = generate_nonce()

    @app.context_processor
    def inject_nonce():
        return dict(nonce=g.get("nonce"))

    # Register blueprints
    from app.blueprints.authentication.signup_auth_bp import signup_auth_bp
    from app.blueprints.authentication.login_auth_bp import login_auth_bp
    app.register_blueprint(signup_auth_bp)
    app.register_blueprint(login_auth_bp)
    
    from app.blueprints.member.member_subscription_bp import member_subscription_bp
    from app.blueprints.member.member_order_bp import member_order_bp  #, alter_menu_item_table
    from app.blueprints.member.member_feedback_bp import member_feedback_bp
    app.register_blueprint(member_subscription_bp)
    app.register_blueprint(member_order_bp)
    app.register_blueprint(member_feedback_bp)

    from app.blueprints.admin.admin_log_bp import admin_log_bp
    from app.blueprints.admin.admin_recipe_bp import admin_recipe_bp
    app.register_blueprint(admin_recipe_bp)
    app.register_blueprint(admin_log_bp)

    # Create all database tables
    with app.app_context():
        db.create_all()

    # Register CLI commands
    register_commands(app)

    # Return Flask app instance
    return app


# Import the User model here to avoid circular import issues
from app.models import User
