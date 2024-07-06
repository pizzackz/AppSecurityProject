import logging

from logging import Logger
from flask import session, flash
from werkzeug.security import check_password_hash
from typing import Optional

from app.models import User, Authentication

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Get user object from db by username
def get_user_by_username(username: str) -> Optional[User]:
    """Retrieve a user by username."""
    user = User.query.filter_by(username=username).first()
    if not user:
        raise ValueError(f"No account found for username '{username}'.")
    return user


# Get auth record from db by user id
def get_auth_by_user_id(user_id: int) -> Optional[Authentication]:
    """Retrieve authentication record by user ID."""
    auth = Authentication.query.get(user_id)
    if not auth:
        raise ValueError(f"No authentication record found for user ID '{user_id}'.")
    return auth


# Check for correct password
def validate_password(auth: Authentication, password: str):
    """Validate the user's password."""
    if not check_password_hash(str(auth.password_hash), password):
        raise ValueError(f"Incorrect password for user ID '{auth.id}'.")


# Handle login errors -- flash message & log error message
def handle_login_error(message: str):
    """Handle login errors by flashing a message and logging the error."""
    flash("Incorrect username or password", "error")
    logger.error(f"Login attempt failed: {message}")
