import secrets
import string
import bleach
import logging

from logging import Logger
from flask import Response, session, redirect, url_for, flash, make_response
from flask_mail import Message
from flask_jwt_extended import get_jwt, get_jwt_identity, unset_jwt_cookies
from typing import Optional, List, Set


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Simple clean input function using bleach
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


# Generate fixed length otp function
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


# Send email function (sending email not work, just printing out mail body for now)
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


# Clear unwanted session data (for clean session states, usually base routes)
def clear_unwanted_session_keys(keys_to_keep: Set[str] = {"_permanent", "_csrf_token"}):
    """
    Utility function to clear specific session keys that are not needed.
    
    Parameters:
    - keys_to_keep (set): A set of keys that should be retained in the session. Default is None.
    
    Returns:
    - None
    """
    keys_to_remove = [key for key in session.keys() if key not in keys_to_keep]
    for key in keys_to_remove:
        session.pop(key, None)


# Check session keys function
def check_session_keys(
    required_keys: List[str], 
    fallback_endpoint: str, 
    flash_message: str = "Your session has expired. Please restart the process.", 
    log_message: str = "Session validation failed"
) -> Optional[Response]:
    """
    Utility function to check if the session contains the necessary keys.

    Parameters:
    - required_keys (list): A list of required keys in the session.
    - fallback_endpoint (str): The endpoint to redirect to if the session data is not valid.
    - flash_message (str, optional): The message to flash if the session data is not valid. Defaults to a generic message.
    - log_message (str, optional): The message to log if the session data is not valid. Defaults to a generic message.

    Returns:
    - None if the session data is valid.
    - Redirect response if the session data is not valid.
    """
    missing_keys = [key for key in required_keys if key not in session]
    if missing_keys:
        session.clear()
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: missing session keys {missing_keys}")
        return response
    return None


# Check signup stage in session function
def check_signup_stage(
    allowed_stages: List[str], 
    fallback_endpoint: str, 
    flash_message: str = "Your session has expired. Please restart the signup process.", 
    log_message: str = "Invalid signup stage"
) -> Optional[Response]:
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
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: {signup_stage} not in {allowed_stages}")
        return make_response(response)

    return None


# Check jwt identity for data type & existence
def check_jwt_identity(fallback_endpoint: str, flash_message: str, log_message: str) -> Optional[Response]:
    """
    Utility function to check if the JWT identity is valid.

    Parameters:
    - fallback_endpoint (str): The endpoint to redirect to if the JWT identity is not valid.
    - flash_message (str): The message to flash if the JWT identity is not valid.
    - log_message (str): The message to log if the JWT identity is not valid.

    Returns:
    - None if the JWT identity is valid.
    - Redirect response if the JWT identity is not valid.
    """
    identity = get_jwt_identity()
    if not identity or not isinstance(identity, dict):
        session.clear()
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: identity is missing or not a dict")
        return response
    return None


# Check jwt identity keys
def check_jwt_identity_keys(required_identity_keys: List[str], fallback_endpoint: str, flash_message: str, log_message: str) -> Optional[Response]:
    """
    Utility function to check if the JWT identity contains the required keys.

    Parameters:
    - required_identity_keys (list): A list of required keys in the JWT identity.
    - fallback_endpoint (str): The endpoint to redirect to if the JWT identity is not valid.
    - flash_message (str): The message to flash if the JWT identity keys are not valid.
    - log_message (str): The message to log if the JWT identity keys are not valid.

    Returns:
    - None if the JWT identity keys are valid.
    - Redirect response if the JWT identity keys are not valid.
    """
    identity = get_jwt_identity()
    missing_keys = [key for key in required_identity_keys if key not in identity]
    if missing_keys:
        session.clear()
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: missing identity keys {missing_keys}")
        return response
    return None


# Check jwt additional claims
def check_jwt_claims(required_claims: List[str], fallback_endpoint: str, flash_message: str, log_message: str) -> Optional[Response]:
    """
    Utility function to check if the JWT contains the required claims.

    Parameters:
    - required_claims (list): A list of required claims in the JWT.
    - fallback_endpoint (str): The endpoint to redirect to if the JWT claims are not valid.
    - flash_message (str): The message to flash if the JWT claims are not valid.
    - log_message (str): The message to log if the JWT claims are not valid.

    Returns:
    - None if the JWT claims are valid.
    - Redirect response if the JWT claims are not valid.
    """
    jwt_claims = get_jwt()
    missing_claims = [claim for claim in required_claims if claim not in jwt_claims]
    if missing_claims:
        session.clear()
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: missing claims {missing_claims}")
        return response
    return None


# Check jwt in general (calls previous 3 functions)
def check_jwt_values(
    required_identity_keys: List[str], 
    required_claims: Optional[List[str]], 
    fallback_endpoint: str, 
    flash_message: str = "An error occurred. Please restart the signup process.",
    log_message: str = "JWT validation failed"
) -> Optional[Response]:
    """
    Utility function to check if the JWT contains the necessary values in the identity and claims.

    Parameters:
    - required_identity_keys (list): A list of required keys in the JWT identity.
    - required_claims (list, optional): A list of required claims in the JWT.
    - fallback_endpoint (str): The endpoint to redirect to if the JWT data is not valid.
    - flash_message (str, optional): The message to flash if the JWT data is not valid. Defaults to a generic message.
    - log_message (str, optional): The message to log if the JWT data is not valid. Defaults to a generic message.

    Returns:
    - None if the JWT data is valid.
    - Redirect response if the JWT data is not valid.
    """
    response = redirect(url_for(fallback_endpoint))

    check = check_jwt_identity(fallback_endpoint, flash_message, log_message)
    if check:
        return check

    check = check_jwt_identity_keys(required_identity_keys, fallback_endpoint, flash_message, log_message)
    if check:
        return check

    if required_claims:
        check = check_jwt_claims(required_claims, fallback_endpoint, flash_message, log_message)
        if check:
            return check

    return None
