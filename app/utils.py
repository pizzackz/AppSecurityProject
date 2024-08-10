import os
import secrets
import string
import bleach
import logging
import imghdr
import hashlib
import requests
import uuid
import smtplib
import requests

from datetime import datetime, timezone
from logging import Logger
from functools import wraps
from sqlalchemy import Table, MetaData, delete
from typing import Optional, List, Set, Dict

from flask import Response, session, redirect, url_for, flash, make_response, current_app
from flask_login import current_user, logout_user
from flask_jwt_extended import get_jwt, get_jwt_identity, unset_jwt_cookies
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app import db, profile_pictures
from app.config.config import Config
from app.models import User, ProfileImage, Log_account, Log_general, Log_transaction

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Initialise variables
logger: Logger = logging.getLogger('tastefully')
VIRUSTOTAL_API_KEY = Config.VIRUSTOTAL_API_KEY
ALLOWED_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png']
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
SMTP_SERVER = Config.SMTP_SERVER
SMTP_PORT = Config.SMTP_PORT
EMAIL_USERNAME = Config.EMAIL_USERNAME
EMAIL_PASSWORD = Config.EMAIL_PASSWORD
FROM_EMAIL = Config.FROM_EMAIL


# Send email function to send emails
def send_email(to_email: str, subject: str, plaintext_body: Optional[str] = None, html_body: Optional[str] = None) -> bool:
    """
    Sends an email to the specified recipient with either a plain text body, 
    an HTML body, or both.

    This function uses the SMTP protocol to send an email. The email can be 
    sent as plain text, HTML, or a multipart message that includes both 
    plain text and HTML versions. The function also handles various SMTP 
    exceptions and logs errors accordingly.

    Args:
        to_email (str): The recipient's email address.
        subject (str): The subject line of the email.
        plaintext_body (Optional[str]): The plain text version of the email body. 
            Defaults to None.
        html_body (Optional[str]): The HTML version of the email body. 
            Defaults to None.

    Returns:
        bool: Returns True if the email was sent successfully, otherwise returns False.

    Raises:
        SMTPAuthenticationError: If the authentication with the SMTP server fails.
        SMTPConnectError: If the connection to the SMTP server fails.
        SMTPException: For other SMTP-related errors.
        Exception: For other general exceptions.
        
    Notes:
        - At least one of `plaintext_body` or `html_body` must be provided.
        - The function logs information about the email sending process, 
          including errors and successful email transmissions.
    """
    try:
        # Create the email container with 'alternative' MIME type
        msg = MIMEMultipart("alternative")
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach plain text and/or HTML parts
        if plaintext_body:
            part1 = MIMEText(plaintext_body, 'plain')
            msg.attach(part1)

        if html_body:
            part2 = MIMEText(html_body, 'html')
            msg.attach(part2)
        
        # Ensure at least one body is provided
        if not plaintext_body and not html_body:
            logger.error("No email body provided")
            return False

        # Send the email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {to_email}")

        # For debugging purposes
        if html_body:
            print(f"HTML Mail body:\n{str(html_body)}")
        elif plaintext_body:
            print(f"Plain Text Mail body:\n{str(plaintext_body)}")

        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication error: {str(e)}")
        return False

    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connection error: {str(e)}")
        return False

    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {str(e)}")
        return False

    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False


# Decorator to handle logout in routes that don't require login but user is logged in
def logout_if_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for("general_bp.logout"))
        return f(*args, **kwargs)
    return decorated_function


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


# Clear session keys that are considered "unwanted", default is to clear all but "_permanent", "_csrf_token", "_flashes"
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
        current_user.login_details.logout()
        logout_user()

        # Unset JWT cookies
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)

        # Flash message and log
        flash("You no access to this page.", "warning")
        logger.warning(log_message)
        return response

    return None


def check_premium_member(keys_to_keep: Optional[Set[str]] = None, fallback_endpoint: str = "login_auth_bp.login", log_message: str = "User is not a premium member"):
    """
    Utility function to check if the user is a premium member. If not, clears session and JWT data, then redirects to login.

    Parameters:
    - keys_to_keep (set, optional): Additional session keys to retain.
    - fallback_endpoint (str, optional): The endpoint to redirect to if the user is not a member. Defaults to login.
    - log_message (str, optional): The message to log if the user is not a member.

    Returns:
    - None if the user is a premium member.
    - Redirect response if the user is not a premium member.
    """
    if current_user.is_authenticated and current_user.type == "member":
        if not(current_user.subscription_plan == "premium" and current_user.subscription_end_date > datetime.now()):
            # Clear session and JWT data
            clear_unwanted_session_keys(extra_keys_to_keep=keys_to_keep)
            current_user.login_details.logout()
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
        current_user.login_details.logout()
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
        logger.error(f"{log_message}: '{auth_stage}' not in {allowed_stages}")
        return response
    return None


# Check expired session
def check_expired_session(
        key_to_check: str,
        fallback_endpoint: str,
        flash_message: str = "Your session has expired. Please re-authenticate with a valid master key.",
        log_message: str = "Session has expired.",
        keys_to_keep: Optional[Set[str]] = None
) -> Optional[Response]:
    """
    Utility function to check if the session is expired based on 'key_to_check'.

    Parameters:
    - key_to_check (str): The key in session that contains the expiry information.
    - fallback_endpoint (str): The endpoint to redirect to if the session data is not valid.
    - flash_message (str, optional): The message to flash if the session is expired. Defaults to a generic message.
    - log_message (str, optional): The message to log if the session is expired. Defaults to a generic message.

    Returns:
    - None if the session is expired.
    - Redirect response if the session data is not valid.
    """
    expired_datetime = session.get(key_to_check)
    if not expired_datetime or expired_datetime < datetime.now(timezone.utc):
        clear_unwanted_session_keys(keys_to_keep)
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        flash(flash_message, 'error')
        logger.error(log_message)
        return response
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


# Verify photo (Put filename into file parameter) - only after saving in file system
def verify_photo(file: str, allowed_image_extensions: List[str] = ALLOWED_IMAGE_EXTENSIONS, max_file_size: int = MAX_FILE_SIZE) -> bool:
    # Check if file exists and is accessible
    if not os.path.isfile(file):
        return False

    # Check the file extension
    filename = os.path.basename(file)
    file_ext = filename.rsplit('.', 1)[-1].lower()
    if file_ext not in allowed_image_extensions:
        return False

    # Check the file content type
    image_type = imghdr.what(file)
    if image_type not in allowed_image_extensions:
        return False

    # Optional: Check the file size
    file_size = os.path.getsize(file)
    if file_size > max_file_size:
        return False

    return True


# Delete old profile picture file from file system if it's not default image
def delete_old_profile_picture(profile_image: ProfileImage):
    """
    Deletes the old profile picture file from the filesystem if it's not the default image.
    Updates the ProfileImage object to set the filename to "default.png".

    Args:
        profile_image (ProfileImage): The ProfileImage object associated with the user.
    """
    if profile_image and profile_image.filename != "default.png":
        file_path = os.path.join(current_app.config['UPLOADED_PROFILEPICTURES_DEST'], profile_image.filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                current_app.logger.info(f"Deleted old profile picture: {file_path}")
                
            # Update the ProfileImage object to reflect the deletion
            profile_image.filename = "default.png"
            profile_image.source = "file_system"
        except Exception as e:
            current_app.logger.error(f"Error deleting old profile picture {file_path}: {e}")


# Save new profile picture file into file system & securely updates ProfileImage object
def save_new_profile_picture(user_id: int, file, profile_image: ProfileImage):
    """
    Saves a new profile picture file securely and updates the ProfileImage object.

    Args:
        user_id (int): The ID of the user uploading the picture.
        file (FileStorage): The uploaded file object.
        profile_image (ProfileImage): The ProfileImage object to update.

    Returns:
        str: The filename of the saved picture.
    """
    # Secure the filename & get its extension
    original_filename = secure_filename(file.filename)
    file_extension = os.path.splitext(original_filename)[1].lower()

    # Generate a unique filename using UUID4 and user ID
    combined = f"{user_id}-{uuid.uuid4()}"
    unique_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    unique_filename = f"{unique_hash}{file_extension}"

    # Save the file
    file.stream.seek(0)
    filename = profile_pictures.save(file, name=unique_filename)

    # Update the ProfileImage object
    profile_image.filename = filename
    profile_image.source = "file_system"
    return filename


# Handle uploading of new profile picture, replacing the old one if needed
def upload_pfp(user: User, profile_image: ProfileImage, new_profile_picture, fallback_endpoint: str):
    """
    Handles the uploading of a new profile picture, replacing the old one if necessary.
    Uses `delete_old_profile_picture` and `save_new_profile_picture`.

    Args:
        user (User): The user uploading the profile picture.
        profile_image (ProfileImage): The ProfileImage object associated with the user.
        new_profile_picture (FileStorage): The new profile picture file.
        fallback_endpoint (str): The endpoint to redirect to in case of errors.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the fallback endpoint.
    """
    if not new_profile_picture:
        flash("Please provide a new profile picture to update it.", "info")
        logger.info(f"User '{user.username}' tried to upload an empty image file.")
        return redirect(url_for(fallback_endpoint))

    image_to_save = new_profile_picture
    try:
        # Scan the new profile picture with VirusTotal
        scan_result = scan_file_with_virustotal(new_profile_picture, VIRUSTOTAL_API_KEY)
        if 'data' in scan_result and scan_result['data'].get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
            flash('The uploaded file is potentially malicious and has not been saved.', 'error')
            logger.warning(f"Potentially malicious file upload attempted by user '{user.username}'.")
            return redirect(url_for(fallback_endpoint))

        print(scan_result)

        # Remove the old profile picture if it exists
        delete_old_profile_picture(profile_image)
        # Save the new profile picture and update the profile image record
        save_new_profile_picture(user.id, image_to_save, profile_image)

        db.session.commit()

        flash("Successfully updated your profile picture!", "success")
        logger.info(f"Profile picture successfully updated for user '{user.username}'")
    except Exception as e:
        flash('An error occurred while uploading your profile picture. Please try again.', 'error')
        logger.error(f"Error uploading profile picture for user '{user.username}': {e}")

    return redirect(url_for(fallback_endpoint))


# Reset user's profile picture to default image
def reset_pfp(user: User, profile_image: ProfileImage, fallback_endpoint: str):
    """
    Resets the user's profile picture to the default image.
    Uses `delete_old_profile_picture`.

    Args:
        user (User): The user resetting their profile picture.
        profile_image (ProfileImage): The ProfileImage object associated with the user.
        fallback_endpoint (str): The endpoint to redirect to in case of errors.

    Returns:
        werkzeug.wrappers.Response: Redirect response to the fallback endpoint.
    """
    if profile_image.filename == "default.png":
        flash("Your profile image is already the default.", "info")
        logger.info(f"User '{user.username}' tried to remove the default profile picture.")
        return redirect(url_for(fallback_endpoint))

    try:
        # Remove the old profile picture and update the profile image record
        delete_old_profile_picture(profile_image)
        db.session.commit()

        flash("Your profile picture has been reset to the default.", "success")
        current_app.logger.info(f"Removed profile picture for user '{user.username}'")
    except Exception as e:
        flash("An error occurred while resetting your profile picture. Please try again later.", "error")
        current_app.logger.error(f"Error removing profile picture for user '{user.username}': {e}")
        return redirect(url_for(fallback_endpoint))

    return redirect(url_for(fallback_endpoint))


# To retrieve the correct url for the stored profile picture
def get_image_url(user: User):
    default_image = 'default.png'
    image_url = url_for('static', filename=f"uploads/profile_pictures/{default_image}")

    # Check if the user has a profile image and its source
    if user.profile_images:
        if user.profile_images.source == 'file_system':
            # Build the full path to the image file
            image_dir_path = current_app.config['UPLOADED_PROFILEPICTURES_DEST']
            image_path = os.path.join(image_dir_path, user.profile_images.filename)
            if os.path.exists(image_path):
                image_url = url_for('static', filename=f'uploads/profile_pictures/{user.profile_images.filename}')
            else:
                logger.warning(f"Profile image for user {user.id} not found: {image_path}")
        elif user.profile_images.source == 'google':
            image_url = user.profile_images.google_url

    return image_url


# Retrieve analysis report from virustotal
def get_virustotal_analysis_report(analysis_id: str, api_key: str) -> dict:
    """
    Retrieve the analysis report from VirusTotal.

    Args:
        analysis_id (str): The analysis ID for the uploaded file.
        api_key (str): The API key for VirusTotal.

    Returns:
        dict: The analysis report from VirusTotal.
    """
    # Prepare request url and header
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error retrieving analysis report from VirusTotal: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error retrieving analysis report from VirusTotal: {e}")
        return {}


# Scan file for potential virus
def scan_file_with_virustotal(file: FileStorage, api_key: str) -> dict:
    """
    Scan a file with VirusTotal using a FileStorage object.

    Args:
        file (FileStorage): The file to be scanned.
        api_key (str): The API key for VirusTotal.

    Returns:
        dict: The analysis results from VirusTotal.
    """
    # Prepare request url and header
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': api_key}

    try:
        # Prepare the file for upload
        file.stream.seek(0)  # Ensure file stream is at the beginning
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            # File successfully uploaded, retrieve the analysis ID
            analysis_id = response.json().get('data', {}).get('id')
            if analysis_id:
                return get_virustotal_analysis_report(analysis_id, api_key)
            else:
                raise Exception("No analysis ID received from VirusTotal.")
        else:
            raise Exception(f"Error uploading file to VirusTotal: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error scanning file with VirusTotal: {e}")
        return {}


# Invalidate sessions (used for admin actions on accounts that have been logged in with multiple sessions)
def invalidate_user_sessions(user_id: int, exclude_current: bool = False) -> None:
    """
    Clears all sessions for the given user_id.

    Args:
        user_id (int): The ID of the user whose sessions are to be cleared.
        exclude_current (bool): Whether to exclude the current session from being cleared.
    """
    try:
        # Reflect the sessions table
        metadata = MetaData()
        sessions_table = Table('sessions', metadata, autoload_with=db.engine)

        # Get the current session ID if excluding the current session
        current_session_id = session.get('_id') if exclude_current else None
        print(f"current session id = {current_session_id}")

        # Query all sessions
        user_sessions = db.session.query(sessions_table).all()

        for user_session in user_sessions:
            record_id = user_session[0]  # Assuming 'id' is at index 0
            session_id = user_session[1]  # Assuming 'session_id' is at index 1
            session_data = user_session[2]  # Assuming 'data' is at index 2

            print(f"Raw session data (truncated): {session_data[:100]}")
            try:
                # Decode the session data into a string
                session_data_str = session_data.decode('utf-8', errors='ignore')
                print(f"session data string = {session_data_str}")

                # Check if the user_id exists in the session data string
                if f"_user_id{user_id}" in session_data_str:
                    # Exclude the current session if specified
                    if exclude_current and session_id == current_session_id:
                        continue
                    # Delete the session using the 'id' column
                    delete_stmt = delete(sessions_table).where(sessions_table.c.id == record_id)
                    db.session.execute(delete_stmt)
            except Exception as e:
                print(f"Failed to process session data for session with id {record_id}: {e}")
        
        db.session.commit()
        
        user_sessions = db.session.query(sessions_table).all()
        print(f"remaining sessions = {user_sessions}")
    except Exception as e:
        db.session.rollback()
        print(f"Error clearing sessions: {e}")


def general_log_setter(): 
    logging.basicConfig(level=logging.INFO, filename="general.log", filemode="a", format="%(asctime)s||%(message)s")
    

def transaction_log_setter():
    logging.basicConfig(level=logging.INFO, filename="transaction.log", filemode="a", format="%(asctime)s||%(message)s")


def account_log_setter():
    logging.basicConfig(level=logging.INFO, filename="account.log", filemode="a", format="%(asctime)s||%(message)s")


# Store logs for 3 kinds (general, transaction based, account related) of logs in database
def log_trans(priority_level, category, user_id, action, info):
    # Get the subdirectory (without the root directory)
    subdirectory = os.path.dirname(__file__)
    root_directory = '/path/to/your/directory'
    if subdirectory.startswith(root_directory):
        subdirectory = subdirectory[len(root_directory):].lstrip(os.path.sep)
    if category=='general':
        new_log = Log_general(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    elif category=='transaction':
        new_log = Log_transaction(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    elif category=='account':
        new_log = Log_account(priority_level=priority_level, category=category, user=user_id, action=action, message_info=info)
    else:
        print("Error! category can only be: \'general\', \'transactions\' or \'account\'")
    
    try:
        db.session.add(new_log)
        db.session.commit()
    except:
        return 'empty'
    

def get_performance_data():
    # This function should fetch and process data from your sources
    data = {
        'response_time': 120,  # in milliseconds
        'uptime': 99.99,       # in percentage
        'error_rate': 0.01,    # in percentage
        'traffic': 1200,       # number of requests
    }
    return data
