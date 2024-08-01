import logging
import base64
import os

from datetime import datetime, timedelta
from logging import Logger, StreamHandler, Formatter
from dotenv import load_dotenv

from flask import Flask, Response, g
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_session import Session
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_uploads import UploadSet, configure_uploads, IMAGES
from pytz import timezone

from app.config.config import Config

from apscheduler.schedulers.background import BackgroundScheduler
import stripe


# Load environment variables from .env file
load_dotenv()

# Initialise CSRF protection, SQLAlchemy, LoginManager, Rate Limiter, Mail, Uploads
csrf: CSRFProtect = CSRFProtect()
db: SQLAlchemy = SQLAlchemy()
jwt: JWTManager = JWTManager()
login_manager: LoginManager = LoginManager()
limiter: Limiter = Limiter(key_func=get_remote_address, default_limits=Config.RATELIMIT_DEFAULT, storage_uri=Config.RATELIMIT_STORAGE_URL)
mail: Mail = Mail()
profile_pictures = UploadSet("profilepictures", IMAGES)


# Setup logger for own logs function
def setup_custom_logger(name: str) -> Logger:
    """Configure a custom logger for the application"""
    logger: Logger = logging.getLogger(name)

    # Remove all handlers associated with logger
    if logger.hasHandlers():
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


# Registering cli commands function
def register_commands(app: Flask) -> None:
    @app.cli.command("seed-db")
    def seed_db():
        """Seed the database with test data"""
        from app.populate_database import seed_database
        with app.app_context():
            seed_database()


# Generate nonce (number used once) function
def generate_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")


# Generate and save nonce (number used once) to request specific object (flask.g)
def set_nonce():
    g.nonce = generate_nonce()


# Set Content Security Policy header to mitigate XSS attacks
def set_security_headers(response: Response) -> Response:
    nonce = g.get("nonce")
    if nonce:
        csp_directives = Config.CSP_DIRECTIVES
        csp_directives["style-src"].append(f"'nonce-{nonce}'")
        csp_directives["script-src"].append(f"'nonce-{nonce}'")
        csp_directives["script-src-attr"].append(f"'nonce-{nonce}'")
        csp_header_value = "; ".join(
            [f"{key} {' '.join(value)}" for key, value in csp_directives.items()]
        )
        response.headers["Content-Security-Policy"] = csp_header_value

    # Set additional secure headers
    for key, value in Config.SECURE_HEADERS.items():
        response.headers[key] = value

    return response


# Inject nonce from 'g' to all templates requiring it
def inject_nonce():
    return dict(nonce=g.get("nonce"))


# To create the actual flask application
def create_app() -> Flask:
    app: Flask = Flask(__name__)  # Create Flask application instance
    app.config.from_object(Config)  # Load configuration from Config class in 'config.py'

    # Initialise extensions
    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    configure_uploads(app, profile_pictures)

    login_manager.login_view = "login_auth_bp.login"
    
    # Custom logger for app logic
    setup_custom_logger("tastefully")

    # Configure Flask-Session to use SQLAlchemy
    app.config["SESSION_SQLALCHEMY"] = db
    Session(app)

    # Register blueprints
    from app.blueprints.home_bp import home_bp
    app.register_blueprint(home_bp)

    from app.blueprints.authentication.login_auth_bp import login_auth_bp
    from app.blueprints.authentication.signup_auth_bp import signup_auth_bp
    from app.blueprints.authentication.recovery_auth_bp import recovery_auth_bp
    app.register_blueprint(login_auth_bp)
    app.register_blueprint(signup_auth_bp)
    app.register_blueprint(recovery_auth_bp)

    from app.blueprints.account_management.admin_control_bp import admin_control_bp
    app.register_blueprint(admin_control_bp)

    from app.blueprints.member.member_profile_bp import member_profile_bp
    from app.blueprints.member.member_subscription_bp import member_subscription_bp
    from app.blueprints.member.member_order_bp import member_order_bp
    from app.blueprints.member.member_feedback_bp import member_feedback_bp
    from app.blueprints.member.member_recipe_bp import member_recipe_bp
    from app.blueprints.member.member_forum_bp import member_forum_bp
    app.register_blueprint(member_profile_bp)
    app.register_blueprint(member_subscription_bp)
    app.register_blueprint(member_order_bp)
    app.register_blueprint(member_feedback_bp)
    app.register_blueprint(member_recipe_bp)
    app.register_blueprint(member_forum_bp)

    from app.blueprints.admin.admin_profile_bp import admin_profile_bp
    from app.blueprints.admin.admin_log_bp import admin_log_bp
    from app.blueprints.admin.admin_recipe_bp import admin_recipe_bp
    from app.blueprints.admin.admin_feedback_bp import admin_feedback_bp
    app.register_blueprint(admin_profile_bp)
    app.register_blueprint(admin_recipe_bp)
    app.register_blueprint(admin_log_bp)
    app.register_blueprint(admin_feedback_bp)

    limiter.limit('50 per minute')(admin_recipe_bp)

    # Create all database tables
    with app.app_context():
        db.create_all()

    # Register CLI commands
    register_commands(app)

    # Register before request, after request, and context processor functions    
    app.before_request(set_nonce)
    app.context_processor(inject_nonce)
    app.after_request(set_security_headers)

    # Return Flask app instance
    return app


# Function to get payment intents to check
def get_payment_intents_to_check():
    from app.models import Payment  # Importing here to avoid circular dependency
    # Query the database for payment intents that are pending or require verification
    pending_payments = Payment.query.filter_by(status='pending').all()
    return [payment.stripe_payment_id for payment in pending_payments]


# Function to check payment status and update database
def check_payment_status():
    from app.models import Member  # Importing here to avoid circular dependency
    # Replace with the logic to get relevant payment intent IDs
    payment_intents = get_payment_intents_to_check()
    for payment_intent_id in payment_intents:
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        if intent.status == 'succeeded':
            user_id = intent.metadata['user_id']
            user = Member.query.get(user_id)
            if user:
                user.subscription_plan = "Premium"
                user.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=30)
                db.session.commit()

# Start the scheduler to run the function periodically
scheduler = BackgroundScheduler()
scheduler.add_job(check_payment_status, 'interval', minutes=10)  # Adjust the interval as needed
scheduler.start()