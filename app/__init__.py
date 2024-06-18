import os
import base64

from dotenv import load_dotenv
from flask import Flask, Response, g
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_session import Session

from app.config import Config


# Load environment variables from .env file
load_dotenv()

# Main file to define a function to create a flask application instance
# Used to "combine" all important blueprints & configurations together in order to run flask app
# Initialise CSRF protection, SQLAlchemy, LoginManager, Rate Limiter
csrf: CSRFProtect = CSRFProtect()
db: SQLAlchemy = SQLAlchemy()
login_manager: LoginManager = LoginManager()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=Config.RATELIMIT_DEFAULT,
    storage_uri=Config.RATELIMIT_STORAGE_URL,
)


# Generate nonce (number used once), randomly generated base64-encoded string
# to be used with CSP to only allow scripts & styles with correct nonce to be
# executed on client-side
def generate_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")


def register_commands(app: Flask) -> None:
    @app.cli.command("seed-db")
    def seed_db():
        """Seed the database with test data"""
        from app.populate_database import seed_database
        with app.app_context():
            seed_database()


def create_app() -> Flask:
    app: Flask = Flask(__name__)  # Create Flask application instance
    app.config.from_object(
        Config
    )  # Load configuration from Config class in 'config.py'

    # Initialise extensions
    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

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
    from app.blueprints.admin.admin_recipe_bp import admin_recipe_bp
    from app.blueprints.member.member_subscription_bp import member_subscription_bp
    from app.blueprints.member.member_order_bp import member_order_bp  #, alter_menu_item_table
    from app.blueprints.member.member_feedback_bp import member_feedback_bp
    from app.blueprints.admin.admin_log_bp import admin_log_bp
    from app.blueprints.auth_bp import auth_bp

    app.register_blueprint(admin_recipe_bp)
    app.register_blueprint(member_subscription_bp)
    app.register_blueprint(member_order_bp)
    app.register_blueprint(member_feedback_bp)
    app.register_blueprint(admin_log_bp)
    app.register_blueprint(auth_bp)

    # Create all database tables
    with app.app_context():
        db.create_all()

    # Register CLI commands
    register_commands(app)

    # Return Flask app instance
    return app


# Import the User model here to avoid circular import issues
from app.models import User


# Import the User model here to avoid circular import issues
from app.models import User
