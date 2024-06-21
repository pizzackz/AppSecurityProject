import os
import base64
import smtplib
import random
import string
import bleach
import logging

from datetime import datetime, timedelta
from logging import Logger
from flask import Flask, Response, session, flash, redirect, url_for, current_app
from functools import wraps
from typing import List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Union, Dict, List, Tuple


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Decorators
# Specific session data required (match keys) decorator
def session_required(keys: List[str], **kwargs):
    """
    Decorator to ensure session data exists for the given keys.

    Args:
        keys (List[str]): The keys to check in the session.
        kwargs (Dict): Optional keyword arguments including:
            - redirect_link (str): The link to redirect if session keys are missing.
            - flash_message (str): The message to flash if session keys are missing.
            - log_message (str): The message to log if session keys are missing.
    """
    # Set default values for optional keyword arguments
    redirect_link: str = kwargs.get("redirect_link", "signup_auth_bp.initial_signup")
    flash_message = kwargs.get('flash_message', "Session expired or invalid access. Please start again.")
    log_message = kwargs.get('log_message', "Missing session keys: {missing_keys}")

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            missing_keys: List[str] = [key for key in keys if key not in session]

            if missing_keys:
                flash(flash_message, "warning")
                logger.warning(log_message.format(missing_keys=missing_keys))
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


# Set session data function
def set_session_data(data: Dict) -> None:
    """Set multiple session data keys at once."""
    for key, value in data.items():
        if value is None:
            session.pop(key, None)
            continue
        session[key] = value


# Generate OTP function
def generate_otp(length: int = 6) -> str:
    """Generate a one-time password (OTP) with a specified length.
    
    Args:
        length (int): The length of the OTP to generate. Default is 6.

    Returns:
        str: The generated OTP.
    """
    return ''.join(random.choices(string.digits, k=length))


# Validate dictionary data structure function
def validate_dict_data_structure(data: Dict, required_keys: List[str]) -> bool:
    """
    General function to validate a dictionary data structure.

    Args:
        data (Dict): The data dictionary to validate.
        required_keys (List[str]): The list of keys that are required in the data dictionary.

    Returns:
        bool: True if the data structure is valid, False otherwise.
    """
    # Return False if data not a dictionary
    if not isinstance(data, dict):
        return False
    
    # Return False if key in required_keys not present in data or value for key has no value
    for key in required_keys:
        if key not in data.keys() or data.get(key) is None:
            return False
    
    # Return True when all checks passed
    return True


# OTP expiry check function
def is_expired_otp(otp_data: Dict, expiry_time: int) -> bool:
    """
    Check if the OTP has expired.

    Args:
        otp_data (Dict): The OTP data dictionary containing value and generation_time.
        expiry_time (int): The expiry time for the OTP in minutes.

    Returns:
        bool: True if the OTP has expired, False otherwise.
    """
    # Return False if generation_time not in otp_data or value is not string
    generation_time: str = otp_data.get("generation_time", None)
    if not generation_time or not isinstance(generation_time, str):
        return False
    
    # Get time from generation_time string, return False if unsuccessful
    try:
        otp_generation_time: datetime = datetime.strptime(generation_time, "%d/%b/%Y %H:%M:%S")
    except ValueError:
        return False
    
    # Return result of whther current time within allowed time frame
    return datetime.now() > otp_generation_time + timedelta(minutes=expiry_time)


# OTP data object validator function
def validate_otp_data(otp_data: Dict, required_keys: List[str], expiry_time: int, otp_length: int = 6) -> bool:
    """
    Validate the OTP data structure and check if it has expired.

    Args:
        otp_data (Dict): The OTP data dictionary.
        required_keys (List[str]): The list of keys that are required in the OTP data dictionary.
        expiry_time (int): The expiry time for the OTP in minutes.
        otp_length (int): The required length of the OTP.

    Returns:
        bool: True if the OTP data structure is valid, not expired, and the OTP is of correct length, False otherwise.
    """
    # Return False if data structure not dict
    if not validate_dict_data_structure(otp_data, required_keys):
        return False
    
    # Return False, if no value for otp_data or length of value doesn't match
    otp_value: str = otp_data.get("value", "")
    if not otp_value or len(otp_value) != otp_length:
        return False
    
    # Return whether otp not expired
    return not is_expired_otp(otp_data, expiry_time)


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


# Function to properly redirect to the correct signup stages (stored in session)
# Each endpoint has own checkers to see whether the user is actually supposed to be at that stage
def signup_stage_redirect(current_stage: str):
    expected_stage: str = session.get("signup_stage", "initial_signup")
    
    # Initalise stage mapping to correct endpoint
    redirect_mapping: Dict[str, Tuple[str, str]] = {
        "initial_signup": ("signup_auth_bp.initial_signup", "Please enter your email and username first before continuing."),
        "otp": ("signup_auth_bp.resend_otp", ""),
        "password": ("signup_auth_bp.set_password", "You were previously setting your password. Please enter your password."),
        "additional_info": ("signup_auth_bp.additional_info", "You have already created an account. Please provide additional details or skip.")
    }

    endpoint, message = redirect_mapping[expected_stage]
    if len(message) >= 1:
        flash(message, "info")
    logger.warning(f"Redirected user from {current_stage} stage to {expected_stage} stage.")
    
    return redirect(url_for(endpoint))  # Redirect user
