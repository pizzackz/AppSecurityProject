import os
import base64
import smtplib
import random
import string
import bleach
import logging
import hashlib

from datetime import datetime, timedelta
from logging import Logger
from flask import Flask, session, flash, current_app
from functools import wraps
from typing import List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Any, Dict, List


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Functions
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
def set_session_data(data: Dict[str, Any]) -> None:
    """Set multiple session data keys at once."""
    for key, value in data.items():
        if value is None:
            session.pop(key, None)
            continue
        session[key] = value


# Set otp session data function
def set_otp_session_data(otp: str) -> None:
    """Set the OTP session data."""
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    current_time = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
    otp_data = {"value": otp_hash, "gen_time": current_time, "verified": False}
    session["otp_data"] = otp_data


# Generate OTP function
def generate_otp(length: int = 6) -> str:
    """Generate a one-time password (OTP) with a specified length.
    
    Args:
        length (int): The length of the OTP to generate. Default is 6.

    Returns:
        str: The generated OTP.
    """
    return ''.join(random.choices(string.digits, k=length))


# Validate otp data based on data type, keys and expiry time
def validate_otp(otp_data: Dict, required_keys: List[str], expiry_time: int = 5) -> None:
    """Validate OTP data structure, keys, and expiry time."""
    validate_otp_data_type(otp_data)
    validate_otp_keys(otp_data, required_keys)
    validate_otp_expiry(otp_data, expiry_time)


# Validate dictionary data structure function
def validate_otp_data_type(otp_data: Dict) -> None:
    """Check it OTP data is a dictionary."""
    if not isinstance(otp_data, dict):
        raise TypeError(f"Session OTP data object has incorrect data type: {type(otp_data)}")


# Validate otp keys
def validate_otp_keys(otp_data: Dict, required_keys: List[str]) -> None:
    """Check if OTP data has all required keys."""
    missing_keys = [key for key in required_keys if key not in otp_data]
    if missing_keys:
        raise KeyError(f"Otp data object has missing keys: {missing_keys}.")


# Validate otp expiry
def validate_otp_expiry(otp_data: Dict, expiry_time: int) -> None:
    """Check if OTP has expired."""
    gen_time = datetime.strptime(otp_data['gen_time'], "%d/%b/%Y %H:%M:%S")
    if datetime.now() > gen_time + timedelta(minutes=expiry_time):
        raise ValueError("Otp has expired.")


# Check otp value
def check_otp_hash(otp_hash: str, otp: str) -> None:
    """Compare the input otp with the otp_hash."""
    input_otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    if otp_hash != input_otp_hash:
        raise ValueError(f"Incorrect OTP value.")


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
        if server:
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

    print(f"otp: {otp}")

    return send_email(to_email, subject, body)


# Handle email verification errors -- flash message & log error message
def handle_email_verify_error(message: str):
    """Handle email verification errors by flashing a message and logging the error."""
    flash("Invalid OTP. Please try again.", "error")
    logger.error(f"Invalid email verification attempt: {message}")
