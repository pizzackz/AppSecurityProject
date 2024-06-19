import os
import base64
import smtplib
import random
import string
import bleach
import logging

from logging import Logger
from flask import Flask, session, flash, redirect, url_for, current_app
from functools import wraps
from typing import List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Decorators
# Specific session data required (match keys) decorator
def session_required(keys: List[str], redirect_link: str = "auth_bp.initial_signup"):
    """Decorator to ensure session data exists for the given keys."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            missing_keys: List[str] = [key for key in keys if key not in session]

            if missing_keys:
                flash("Session expired or invalid access. Please start again.", "warning")
                logger.warning(f"Missing session keys: {missing_keys}")
                return redirect(url_for(redirect_link))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Functions
# Registering cli commands function
def register_commands(app: Flask) -> None:
    @app.cli.command("seed-db")
    def seed_db():
        """Seed the database with test data"""
        from app.populate_database import seed_database
        with app.app_context():
            seed_database()


# Generate nonce (number used once), randomly generated base64-encoded string
# to be used with CSP to only allow scripts & styles with correct nonce to be
# executed on client-side function
def generate_nonce() -> str:
    return base64.b64encode(os.urandom(16)).decode("utf-8")


# Clean input function
def clean_input(data: str, strip: bool = True) -> str:
    """Sanitise and strip input data using bleach."""
    if not strip: return bleach.clean(data)

    return bleach.clean(data.strip())


# Clear specific session data
def clear_session_data(keys: List[str]) -> None:
    """Clear specific session data keys."""
    for key in keys:
        session.pop(key, None)


# Clear temporary singup session data function
def clear_signup_session() -> None:
    """Clear the signup-related session data (username, email, otp)."""
    clear_session_data(["username", "email", "otp"])


# Set session data function
def set_session_data(data: Dict) -> None:
    """Set multiple session data keys at once."""
    for key, value in data.items():
        session[key] = value


# Handle user (mainly member) not found function
def handle_user_not_found(username: str, email: str, user_type: str = "User") -> None:
    """Handle the case where a user (usually member) is not found in the database."""
    flash(f"{user_type} not found. Please start again.", "danger")
    logger.error(f"{user_type} not found for username: {username}, email: {email}.")
    clear_signup_session()


# Generate OTP function
def generate_otp(length: int = 6) -> str:
    """Generate a one-time password (OTP) with a specified length.
    
    Args:
        length (int): The length of the OTP to generate. Default is 6.

    Returns:
        str: The generated OTP.
    """
    return ''.join(random.choices(string.digits, k=length))


# General send email function
def send_email(to_email: str, subject: str, body: str) -> Optional[bool]:
    """
    Send an email securely using Gmail's SMTP server.

    Args:
        to_email (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The body of the email.
    
    Raises:
        Exception: If there is an issue sending the email.
    """
    GMAIL_USER: str = current_app.config.get("GMAIL_USER")
    GMAIL_PASSWORD: str = current_app.config.get("GMAIL_PASSWORD")

    msg = MIMEMultipart()
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg["subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        # Establish secure session with Gmail's outgoing SMTP server using TLS
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Start TLS for security
        server.login(GMAIL_USER, GMAIL_PASSWORD)  # Login with credentials

        # Send email
        text = msg.as_string()
        server.sendmail(GMAIL_USER, to_email, text)

        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
    finally:
        server.quit()  # Terminate SMTP session


# Send OTP to stated email function
def send_otp_email(to_email: str, otp: str) -> Optional[bool]:
    """
    Send an OTP email to the specified email address.

    Args:
        to_email (str): The recipient's email address.
        otp (str): The one-time password to send.
    
    Raises:
        Exception: If there is an issue sending the email.
    """
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp}"
    return send_email(to_email, subject, body)
