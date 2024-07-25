import secrets
import string
import bleach
import logging
import imghdr

from logging import Logger
from flask import Response, session, redirect, url_for, flash, make_response
from flask_mail import Message
from flask_login import current_user, logout_user
from flask_jwt_extended import get_jwt, get_jwt_identity, unset_jwt_cookies
from typing import Optional, List, Set, Dict


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
def clear_unwanted_session_keys(extra_keys_to_keep: Optional[Set[str]] = None):
    """
    Utility function to clear specific session keys that are not needed.
    
    Parameters:
    - keys_to_keep (set): A set of keys that should be retained in the session. Default is None.
    
    Returns:
    - None
    """
    keys_to_keep = {"_permanent", "_csrf_token", "_flashes"}
    if extra_keys_to_keep:
        keys_to_keep = keys_to_keep.union(extra_keys_to_keep)

    keys_to_remove = [key for key in session.keys() if key not in keys_to_keep]
    clear_session_data(keys_to_remove)


# Check user is member function
def check_member(keys_to_keep: Optional[Set[str]] = None, fallback_endpoint: str = "login_auth_bp.login", log_message: str = "User is not a member"):
    """
    Utility function to check if the user is a member. If not, clears session and JWT data, then redirects to login.

    Parameters:
    - keys_to_keep (set, optional): Additional session keys to retain.
    - fallback_endpoint (str, optional): The endpoint to redirect to if the user is not a member. Defaults to login.
    - log_message (str, optional): The message to log if the user is not a member.

    Returns:
    - None if the user is a member.
    - Redirect response if the user is not a member.
    """
    if not current_user.is_authenticated or not current_user.type == "member":
        # Clear session and JWT data
        clear_unwanted_session_keys(extra_keys_to_keep=keys_to_keep)
        logout_user()

        # Unset JWT cookies
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)

        # Flash message and log
        flash("You no access to this page.", "warning")
        logger.warning(log_message)
        return response

    return None


# Check user is admin function
def check_admin(keys_to_keep: Optional[Set[str]] = None, fallback_endpoint: str = "login_auth_bp.login", log_message: str = "User is not an Admin"):
    """
    Utility function to check if the user is an admin. If not, clears session and JWT data, then redirects to login.

    Parameters:
    - keys_to_keep (set, optional): Additional session keys to retain.
    - fallback_endpoint (str, optional): The endpoint to redirect to if the user is not a member. Defaults to login.
    - log_message (str, optional): The message to log if the user is not a member.

    Returns:
    - None if the user is a member.
    - Redirect response if the user is not a member.
    """
    if not current_user.is_authenticated or not current_user.type == "admin":
        # Clear session and JWT data
        clear_unwanted_session_keys(extra_keys_to_keep=keys_to_keep)
        logout_user()

        # Unset JWT cookies
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)

        # Flash message and log
        flash("You have no access to this page.", "warning")
        logger.warning(log_message)
        return response

    return None


# Check session keys function
def check_session_keys(
    required_keys: List[str], 
    fallback_endpoint: str, 
    flash_message: str = "Your session has expired. Please restart the process.", 
    log_message: str = "Session validation failed",
    keys_to_keep: Optional[Set[str]] = None
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
        clear_unwanted_session_keys(keys_to_keep)
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: missing session keys {missing_keys}")
        return response
    return None


# Check authentication stage (signup, login, recovery) in session function
def check_auth_stage(
    auth_process: str,
    allowed_stages: List[str], 
    fallback_endpoint: str, 
    flash_message: str = "Your session has expired. Please restart the signup process.", 
    log_message: str = "Invalid signup stage",
    keys_to_keep: Optional[Set[str]] = None
) -> Optional[Response]:
    """
    Utility function to check if the current stage is allowed.

    Parameters:
    - auth_process (str): The name stored as key in the session to identify the authentication process stages.
    - allowed_stages (list): A list of allowed authentication stages.
    - fallback_endpoint (str): The endpoint to redirect to if the current stage is not allowed.
    - flash_message (str): The message to flash if the current stage is not allowed.
    - log_message (str): The message to log if the current stage is not allowed.

    Returns:
    - None if the current stage is allowed.
    - Redirect response if the current stage is not allowed.
    """
    auth_stage = session.get(auth_process)

    if not auth_stage or auth_stage not in allowed_stages:
        clear_unwanted_session_keys(keys_to_keep)
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: {auth_stage} not in {allowed_stages}")
        return make_response(response)
    
    return None


# Check jwt identity for data type & existence
def check_jwt_identity(fallback_endpoint: str, flash_message: str, log_message: str, keys_to_keep: Optional[Set[str]] = None) -> Optional[Response]:
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
        clear_unwanted_session_keys(keys_to_keep)
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: identity is missing or not a dict")
        return response
    return None


# Check jwt identity keys
def check_jwt_identity_keys(required_identity_keys: List[str], fallback_endpoint: str, flash_message: str, log_message: str, keys_to_keep: Optional[Set[str]] = None) -> Optional[Response]:
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
        clear_unwanted_session_keys(keys_to_keep)
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(f"{log_message}: missing identity keys {missing_keys}")
        return response
    return None


# Check jwt additional claims
def check_jwt_claims(required_claims: List[str], fallback_endpoint: str, flash_message: str, log_message: str, keys_to_keep: Optional[Set[str]] = None) -> Optional[Response]:
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
        clear_unwanted_session_keys(keys_to_keep)
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
    log_message: str = "JWT validation failed",
    keys_to_keep: Optional[Set[str]] = None
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

    check = check_jwt_identity(fallback_endpoint, flash_message, log_message, keys_to_keep)
    if check:
        return check

    check = check_jwt_identity_keys(required_identity_keys, fallback_endpoint, flash_message, log_message, keys_to_keep)
    if check:
        return check

    if required_claims:
        check = check_jwt_claims(required_claims, fallback_endpoint, flash_message, log_message, keys_to_keep)
        if check:
            return check

    return None


# Store data in session
def set_session_data(data: Dict):
    for key, value in data.items():
        session[key] = value
    print(f"Session data set: {session}")


# Retrieve data from session
def get_session_data(keys: List[str]):
    data = {key: session.get(key) for key in keys}
    print(f"Session data retrieved: {data}")
    return data


# Clear session data
def clear_session_data(keys: List[str]):
    for key in keys:
        session.pop(key, None)
    print(f"Session data cleared: {keys}")


# Verify photo (Put filename into file parameter)
def verify_photo(file):
    image_type = imghdr.what(file)
    if image_type is None:
        return False
    if file == '':
        return False
    picture_filename = file.split('.')
    if len(picture_filename) != 2:
        return False
    return True

