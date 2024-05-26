import os


# Define 'Config' class for all app configurations
class Config:
    # Secret key for session management & CSRF protection
    SECRET_KEY = (
        os.environ.get("SECRET_KEY") or "secret_key_123"
    )

    # Change the value for 'SQLALCHEMY_DATABASE_URI' to whatever you used on your local computer to connect
    # to your local database
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL")
        or "mysql://root:password123@localhost/recipes_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True  # Prevent Javascript from accessing session cookies
    SESSION_COOKIE_SECURE = True  # Ensure session cookies only sent over HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"  # Mitigate CSRF by limiting cross-site requests

    # Base CSP settings
    CSP_DIRECTIVES = {
        'default-src': ["'self'"],
        'style-src': ["'self'", 'https://cdn.jsdelivr.net'],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
        'font-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'frame-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
    }
