import os
import random  # Might be used for more secure secret keys
from datetime import timedelta
from dotenv import load_dotenv


# Load environment file
load_dotenv("../.env")

# Base directory path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


# Define 'Config' class for all app configurations
class Config:
    # Secret key for session management & CSRF protection
    SECRET_KEY = (
        os.environ.get("SECRET_KEY") or os.urandom(24).hex()
    )

    # Change the value for 'SQLALCHEMY_DATABASE_URI' to whatever you used on your local computer to connect
    # to your local database
    SQLALCHEMY_DATABASE_URI = "mysql://root:password123@localhost/tastefully"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get("WTF_CSRF_SECRET_KEY") or os.urandom(24).hex()

    # Secure cookie settings
    SESSION_COOKIE_HTTPONLY = True  # Prevent Javascript from accessing session cookies
    SESSION_COOKIE_SECURE = True  # Ensure session cookies only sent over HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"  # Mitigate CSRF by limiting cross-site requests
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Set session lifetime to 1 hour(s)

    # Session storage configurations
    SESSION_TYPE = "sqlalchemy"  # Store session data in database

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
    GMAIL_USER = os.getenv("GMAIL_USER")
    GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")

    # Stripe configuration
    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')

    # OpenAI API key
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

