import os
from datetime import timedelta
from dotenv import load_dotenv


# Load .env file variables
load_dotenv()

# Base directory path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


# Define 'Config' class for all app configurations
class Config:
    # Secret key
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32).hex())

    # JWT configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_CSRF_PROTECT = False

    # Change the value for 'SQLALCHEMY_DATABASE_URI' to whatever you used on your local computer to connect
    # to your local database
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF protection
    WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY', os.urandom(32).hex())
    WTF_CSRF_ENABLED = True
    WTF_CSRF_FIELD_NAME = "_csrf_token"

    # Secure cookie settings
    SESSION_COOKIE_HTTPONLY = True  # Prevent Javascript from accessing session cookies
    SESSION_COOKIE_SECURE = True  # Ensure session cookies only sent over HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"  # Mitigate CSRF by limiting cross-site requests
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Set session lifetime to 1 hour(s)

    # Session storage configurations
    SESSION_TYPE = "sqlalchemy"  # Store session data in database
    SESSION_PERMANENT = True

    # Base CSP settings
    CSP_DIRECTIVES = {
        'default-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdn.tiny.cloud'],
        'style-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdn.tiny.cloud'],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdn.ckeditor.com', 'https://js.stripe.com/v3/', 'https://cdn.tiny.cloud'],
        'font-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
        'img-src': ["'self'", 'data:', 'https://sp.tinymce.com'],
        'connect-src': ["'self'", 'https://cdn.tiny.cloud'],
        'frame-src': ["'self'", 'https://js.stripe.com'],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'script-src-attr': ["'self'", 'https://js.stripe.com'],
    }

    # Rate Limiting
    RATELIMIT_DEFAULT = ["200 per day", "20 per hour"]
    RATELIMIT_STORAGE_URL = "memory://"  # Store rate limit counters in memory

    # Secure headers
    SECURE_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
    }

    # Email configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = os.getenv("MAIL_PORT")
    MAIL_USER = os.getenv("MAIL_USER")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")
    MAIL_USE_SSL = False
    MAIL_USE_TLS = True

    # Stripe configuration
    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')

