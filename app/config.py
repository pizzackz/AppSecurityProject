import os


# Define 'Config' class for all app configurations
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "secret_key_123"  # Secret key for session management & CSRF protection

    # Change Database configuration after MySQL is set up
    # SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "slite:///site.db"  # Database configuration

    SESSION_COOKIE_HTTPONLY = True  # Prevent Javascript from accessing session cookies
    SESSION_COOKIE_SECURE = True  # Ensure session cookies only sent over HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"  # Mitigate CSRF by limiting cross-site requests
