import hashlib
import secrets
import string
import bleach
import logging

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import session, redirect, url_for, flash
from flask_mail import Message
from flask_jwt_extended import create_access_token, decode_token
from werkzeug.wrappers.response import Response
from typing import Optional, Dict, List

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
    # from app import mail

    # msg = Message(subject, sender=current_app.config['MAIL_USERNAME'], recipients=[to_email])
    # msg.body = body

    # try:
    #     mail.send(msg)
    #     logger.info(f'Email sent to {to_email} with subject "{subject}"')
    #     return True
    # except Exception as e:
    #     logger.error(f"Failed to send email to {to_email} with subject '{subject}': {e}")
    #     return False

    print(f"Mail message body:\n{body}")
    return True


# Check signup stage in session function
def check_signup_stage(allowed_stages: List[str], fallback_endpoint: str, flash_message: str, log_message: str) -> Optional[Response]:
    """
    Utility function to check if the current signup stage is allowed.

    Parameters:
    - allowed_stages (list): A list of allowed signup stages.
    - fallback_endpoint (str): The endpoint to redirect to if the current stage is not allowed.
    - flash_message (str): The message to flash if the current stage is not allowed.
    - log_message (str): The message to log if the current stage is not allowed.

    Returns:
    - None if the current stage is allowed.
    - Redirect response if the current stage is not allowed.
    """
    signup_stage = session.get('signup_stage')
    
    if not signup_stage or signup_stage not in allowed_stages:
        session.clear()
        flash(flash_message, 'error')
        logger.error(log_message)
        return redirect(url_for(fallback_endpoint))
    
    return None

