import hashlib
import secrets
import string
import bleach
import logging

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import current_app
from flask_mail import Message
from flask_jwt_extended import create_access_token, decode_token
from typing import Dict

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')

def clean_input(data: str, strip: bool = True) -> str:
    """
    Sanitize and strip input data using bleach.
    
    Args:
        data (str): The input data to sanitize.
        strip (bool): Whether to strip whitespace from the input data.

    Returns:
        str: The sanitized data.
    """
    if not strip:
        return bleach.clean(data)
    return bleach.clean(data.strip())


def generate_otp(length: int = 6) -> str:
    """
    Generate a secure OTP using a cryptographically secure random number generator.
    
    Args:
        length (int): Length of the OTP to generate.

    Returns:
        str: The generated OTP.
    """
    characters = string.digits
    otp = ''.join(secrets.choice(characters) for _ in range(length))
    return otp


def hash_otp(otp: str) -> str:
    """
    Hash the OTP using SHA-256.
    
    Args:
        otp (str): The OTP to hash.

    Returns:
        str: The hashed OTP.
    """
    return hashlib.sha256(otp.encode()).hexdigest()


def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Send an email using Flask-Mail.
    
    Args:
        to_email (str): Recipient email address.
        subject (str): Email subject.
        body (str): Email body.

    Returns:
        bool: True if email sent successfully, False otherwise.
    """
    from app import mail

    msg = Message(subject, sender=current_app.config['MAIL_USERNAME'], recipients=[to_email])
    msg.body = body

    try:
        mail.send(msg)
        logger.info(f'Email sent to {to_email} with subject "{subject}"')
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email} with subject '{subject}': {e}")
        return False
