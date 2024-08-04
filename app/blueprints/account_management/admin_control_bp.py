import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Optional, Set

from flask import Blueprint, request, session, redirect, render_template, flash, url_for, make_response, Response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash

from app import db
from app.models import Admin, MasterKey, LockedAccount, PasswordResetToken
from app.forms.forms import CreateAdminForm, LockAdminForm, DeleteAdminForm
from app.forms.auth_forms import OtpForm
from app.utils import logout_if_logged_in, clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_session_keys, check_expired_session, set_session_data, check_auth_stage, check_jwt_values, get_image_url


# Initialise variables
admin_control_bp = Blueprint("admin_control_bp", __name__, url_prefix="/start")
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "account_management/admin"
ESSENTIAL_KEYS = {"key_id", "key_expiry", "session_expiry"}
ADMIN_SPECIFIC_ESSENTIAL_KEYS = {"key_id", "key_expiry", "session_expiry", "admin_id"}


# Check function to call other check functions for admin control blueprint
def admin_control_checks(keys_to_keep: Optional[Set[str]] = None) -> Optional[Response]:
    # Check whether session has master key values
    no_session_keys = check_session_keys(
        required_keys=['key_id', 'key_expiry', 'session_expiry'],
        fallback_endpoint='admin_control_bp.start',
        flash_message="Your session has expired. Please re-authenticate with a valid master key.",
        log_message="Admin control panel session invalidated",
        keys_to_keep=keys_to_keep
    )
    if no_session_keys:
        return no_session_keys
    
    # Check whether session expired
    is_expired_session = check_expired_session(
        key_to_check='session_expiry',
        fallback_endpoint='admin_control_bp.start',
        flash_message='Your session has expired. Please re-authenticate again with a valid master key.',
        log_message='Admin control panel session has expired.',
        keys_to_keep=keys_to_keep
    )
    if is_expired_session:
        return is_expired_session
    
    # Check whether master key expired
    is_expired_key = check_expired_session(
        key_to_check='session_expiry',
        fallback_endpoint='admin_control_bp.start',
        flash_message='The master key used has expired. Please re-authenticate again with another valid master key.',
        log_message='Admin control panel master key used has expired.',
        keys_to_keep=keys_to_keep
    )
    if is_expired_key:
        return is_expired_key

    # Check whether master key exists
    master_key = MasterKey.query.get(session.get('key_id'))
    if not master_key:
        clear_unwanted_session_keys(keys_to_keep)
        flash("You session has expired. Please re-authenticate again with a valid master key.", "error")
        logger.warning(f"A user tried to enter admin control with non-existent master key.")
        response = make_response(redirect(url_for("admin_control_bp.start")))
        unset_jwt_cookies(response)
        return response
    
    return None


# Initial route to authroise "admin" user into admin control pages using master key
@admin_control_bp.route("/", methods=['GET', 'POST'])
@logout_if_logged_in
def start():
    # Clear all session data and jwt tokens
    clear_unwanted_session_keys()

    # Check wheter user got redirected after session timed out
    if request.args.get("expired_session") == "True":
        flash("The session has expired. You will need to re-authenticate again.", "info")
        logger.info("Session has expired and user has been redirected back to reauthenticate.")
        response = redirect(url_for('admin_control_bp.start'))
        unset_jwt_cookies(response)
        return response

    if request.method == "POST":
        form_data = request.form.get("master_key")

        # Check if have input
        if not form_data:
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response

        # Sanitise input
        master_key_input = clean_input(form_data)

        # Check if input has exactly length of 64 characters
        if len(form_data) != 64:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter a fake admin key with length of '{len(form_data)}' characters.")
            response = redirect(url_for("admin_control_bp.start"))
            return response

        # Check if have existing master key record of same value
        master_key_record = MasterKey.query.filter_by(value=master_key_input).first()
        if not master_key_record:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter admin control without having correct master key.")
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response
        
        # Check if master key is outdated/ expired
        if master_key_record.expires_at <= datetime.now():
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter admin control using an expired master key.")
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response

        # Create & store session data
        session_data = {
            "key_id": master_key_record.id,
            'key_expiry': master_key_record.expires_at,
            'session_expiry': datetime.now(timezone.utc) + timedelta(minutes=30)
        }
        set_session_data(session_data)

        flash("Succesfully authenticated. You are given 30mins before needing to re-authenticate.", "success")
        logger.info("A user was successfully authenticated to access the admin control pages.")

        response = redirect(url_for("admin_control_bp.view_admins"))
        unset_jwt_cookies(response)
        return response

    response = make_response(render_template(f"{TEMPLATE_FOLDER}/start.html"))
    unset_jwt_cookies(response)
    return response


# Admin control view admins route for viewing all admin accounts
@admin_control_bp.route("/1", methods=['GET', 'POST'])
def view_admins():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    # Redirect to create admin when clicked on create admin
    if request.args.get("action") == "create":
        return redirect(url_for("admin_control_bp.create_admin"))

    # Redirect to admin details when clicked on any entry provided there is an admin id
    if request.method == "POST":
        # Check whether have admin id in form
        admin_id = request.form.get("admin_id")
        if not admin_id:        
            flash("Failed to select admin. Please try again.", "error")
            logger.warning("Failed to retrieve admin ID when trying to view specific admin account details.")
            return redirect(url_for("admin_control_bp.view_admins"))

        session['admin_id'] = admin_id
        logger.info(f"Admin '{admin_id}' selected for viewing details.")
        return redirect(url_for("admin_control_bp.view_admin_details"))

    # Fetch all admin accounts
    admins = Admin.query.all()

    # Define which attributes to display in admin list view
    admin_list_data = [{
        "image": get_image_url(admin),
        "id": admin.id,
        "username": admin.username,
        "email": admin.email,
        "created_at": admin.created_at,
        "last_login": admin.login_details.last_login if admin.login_details else None,
        "account_locked": admin.account_status.is_locked if admin.account_status else False,
        "unlock_request": (
            LockedAccount.query.filter_by(id=admin.id).first().unlock_request
            if admin.account_status.is_locked and LockedAccount.query.filter_by(id=admin.id).first()
            else False
        ),
        "is_online": admin.login_details.is_active
    } for admin in admins]

    # Render the view admins template with fetched data
    return render_template(f"{TEMPLATE_FOLDER}/view_admins.html", admin_data=admin_list_data, count=len(admin_list_data))


# Specific admin account view route
@admin_control_bp.route("/2", methods=['GET', 'POST'])
def view_admin_details():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result

    # Check admin_id exists in session
    no_admin_id_in_session = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admins',
        flash_message="No admin selected. Please select an admin from the list.",
        log_message="Attempted to view admin details without selecting an admin.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_admin_id_in_session:
        return no_admin_id_in_session

    # Check whether admin account exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        flash("Admin account not found.", "error")
        logger.warning(f"Admin account with ID '{admin_id}' not found.")
        return redirect(url_for("admin_control_bp.view_admins"))

    # Properly handle different actions
    action = request.args.get('action') or request.form.get("action")
    if action:
        if action == "back":
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            return redirect(url_for("admin_control_bp.view_admins"))

        if action == "lock":
            flash("Please provide a reason for locking the admin account.", "info")
            logger.info(f"Attempting to lock admin account '{admin.username}'.")
            return redirect(url_for("admin_control_bp.lock_admin"))

        if action == "unlock":
            logger.info(f"Attempting to unlock admin account '{admin.username}'.")
            return redirect(url_for("admin_control_bp.unlock_admin"))

        if action == "delete":
            flash(f"Please re-enter the master key to confirm that you want to delete the account.", "info")
            logger.info(f"Attempting to delete admin account '{admin.username}'.")
            return redirect(url_for("admin_control_bp.delete_admin"))

        if action == "reset_password":
            logger.info(f"Attempting to send reset password link to admin email '{admin.email}'.")
            return redirect(url_for("admin_control_bp.send_password_link"))

        if action == "generate_key":
            logger.info(f"Attempting to regenerate a new admin key for admin account '{admin.username}'.")
            return redirect(url_for("admin_control_bp.generate_admin_key"))

        if action == "view_activities":
            # TODO: Redirect to Jacen's route to display all admin activities
            return redirect(url_for("admin_control_bp.view_admin_details"))

    # Prepare data for rendering
    admin_data = {
        "status": "Online" if admin.login_details.is_active else "Offline",
        "locked": admin.account_status.is_locked,
        "image": get_image_url(admin),
        "id": admin.id,
        "username": admin.username,
        "email": admin.email,
        "phone_number": admin.phone_number,
        "address": admin.address,
        "postal_code": admin.postal_code,
        "created_at": admin.created_at,
        "updated_at": admin.updated_at,
        "failed_login_attempts": admin.account_status.failed_login_attempts,
        "last_failed_login_attempt": admin.account_status.last_failed_login_attempt,
        "last_login": admin.login_details.last_login,
        "last_logout": admin.login_details.last_logout,
        "login_count": admin.login_details.login_count,
        "unlock_request": (
            LockedAccount.query.filter_by(id=admin.id).first().unlock_request
            if admin.account_status.is_locked and LockedAccount.query.filter_by(id=admin.id).first()
            else False
        ),
        "locked_reason": (
            LockedAccount.query.filter_by(id=admin.id).first().locked_reason
            if admin.account_status.is_locked and LockedAccount.query.filter_by(id=admin.id).first()
            else False
        )
    }

    # Render specific admin view template with fetched data
    return render_template(f"{TEMPLATE_FOLDER}/view_admin_details.html", admin=admin_data)


# Lock admin route
@admin_control_bp.route("/2/lock_admin", methods=['GET', 'POST'])
def lock_admin():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    # Redirect to view admin details & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for('admin_control_bp.view_admin_details'))
        unset_jwt_cookies(response)
        flash("Admin locking process cancelled.", "info")
        logger.info("User opted to cancel the admin locking process.")
        return response
    
    # Check whether admin_id in session
    no_admin_id = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admin_details',
        flash_message='There is no admin selected to lock. Please choose an admin account to lock.',
        log_message='User tried to lock an admin account without provided the account id',
        keys_to_keep=ADMIN_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_admin_id:
        return no_admin_id

    # Check whether account actually exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the admin account to lock", "error")
        logger.error(f"User tried lock an admin without providing the id for an existing account")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    # Check whether account is not locked
    locked_account = LockedAccount.query.get(admin_id)
    if locked_account:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Admin account is already locked.", "error")
        logger.error(f"User tried to lock admin account '{admin.username}' even though it is already locked.")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    form = LockAdminForm()
    if request.method == "POST" and form.validate_on_submit():
        # Sanitise input
        reason = clean_input(form.reason.data)

        # Try sending email using utility send_email function
        email_body = f"Your account has been locked. The reason is:\n{reason}"
        if send_email(admin.email, "Account Locked", email_body):
            if Admin.lock_account(id_to_lock=admin_id, locked_reason=reason):
                clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
                flash("Successfully locked admin account!", "success")
                logger.info(f"Successfully locked admin with admin id of '{id}' with reason:\n{reason}")
                return redirect(url_for("admin_control_bp.view_admin_details"))
            else:
                clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
                flash("An error occurred while unlocking the account.")
                return redirect(url_for("admin_control_bp.view_admin_details"))
        else:
            clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
            flash("An error occurred while locking the account.")
            logger.error(f"Failed to send email to inform admin '{admin.username}' that their account has been locked.")
            return redirect(url_for("admin_control_bp.view_admin_details"))

    # Render the lock admin template
    return render_template(f"{TEMPLATE_FOLDER}/lock_admin.html", form=form)


# Unlock admin route
@admin_control_bp.route("/2/unlock_admin", methods=['GET'])
def unlock_admin():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    # Check whether admin_id in session
    no_admin_id = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admin_details',
        flash_message='There is no admin selected to unlock. Please choose an admin account to unlock.',
        log_message='User tried to unlock an admin account without provided the account id',
        keys_to_keep=ADMIN_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_admin_id:
        return no_admin_id

    # Check whether account actually exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the admin account to unlock", "error")
        logger.error(f"User tried to unlock an admin without providing the id for an existing account")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    # Check wether account is actually locked
    locked_account = LockedAccount.query.get(admin_id)
    if not locked_account:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Admin account isn't currently locked.", "error")
        logger.error(f"User tried to unlock admin account '{admin.username}' even though it is not locked.")
        return redirect(url_for("admin_control_bp.view_admin_details"))

    # Try sending email using utility send_email function
    email_body = "Your account has been unlocked."
    if send_email(admin.email, "Account Unlocked", email_body):
        if Admin.unlock_account(admin_id):
            clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
            flash("Successfully unlocked admin account!", "success")
            logger.info(f"Successfully unlocked admin with admin id of '{id}'.")
            return redirect(url_for("admin_control_bp.view_admin_details"))
        else:
            clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
            flash("An error occurred while locking the account.")
            return redirect(url_for("admin_control_bp.view_admin_details"))
    else:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("An error occurred while unlocking the account.")
        logger.error(f"Failed to send email to inform admin '{admin.username}' that their account has been unlocked.")
        return redirect(url_for("admin_control_bp.view_admin_details"))


# Delete admin route
@admin_control_bp.route("/2/delete_admin", methods=['GET', 'POST'])
def delete_admin():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result

    # Redirect to view admins & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        keys_to_keep = {key for key in ESSENTIAL_KEYS}.add("admin_id")
        clear_unwanted_session_keys(keys_to_keep)
        response = redirect(url_for('admin_control_bp.view_admin_details'))
        unset_jwt_cookies(response)
        flash("Admin deletion process cancelled.", "info")
        logger.info("User opted to cancel the admin deletion process.")
        return response
    
    # Check whether admin_id in session
    no_admin_id = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admins',
        flash_message='There is no admin selected to delete. Please choose an admin account to delete.',
        log_message='User tried deleting an admin account without provided the account id',
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_admin_id:
        return no_admin_id

    # Check whether account actually exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        flash("Couldn't find the admin account to delete", "error")
        logger.error(f"User tried deleting an admin without providing the id for an existing account")
        return redirect(url_for("admin_control_bp.view_admins"))
    
    form = DeleteAdminForm()
    if request.method == "POST" and form.validate_on_submit():
        # Check if have input
        form_data = request.form.get("master_key")
        if not form_data:
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response

        # Sanitise input
        master_key_input = clean_input(form_data)

        # Check if input has exactly length of 64 characters
        if len(form_data) != 64:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter a fake admin key with length of '{len(form_data)}' characters.")
            response = redirect(url_for("admin_control_bp.delete_admin"))
            return response

        # Check if have existing master key record of same value
        master_key_record = MasterKey.query.filter_by(value=master_key_input).first()
        if not master_key_record:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter admin control without having correct master key.")
            response = redirect(url_for("admin_control_bp.delete_admin"))
            unset_jwt_cookies(response)
            return response

        # Check if master key is outdated/ expired
        if master_key_record.expires_at <= datetime.now():
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to delete an admin account using an expired master key.")
            response = redirect(url_for("admin_control_bp.delete_admin"))
            unset_jwt_cookies(response)
            return response

        # Try sending email using utility send_email function
        email_body = "Your account has been deleted."
        if send_email(admin.email, "Deleted Account", email_body):
            Admin.delete(admin_id)
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            flash("Successfully deleted admin account!", "success")
            logger.info(f"Successfully deleted admin with admin id of '{id}'")
            return redirect(url_for("admin_control_bp.view_admins"))
        else:
            flash("An error occurred while deleting the account.")
            logger.error(f"Failed to send email to inform admin '{admin.username}' that their account has been deleted.")
            return redirect(url_for("admin_control_bp.view_admin_details"))

    # Render the delete admin template
    return render_template(f"{TEMPLATE_FOLDER}/delete_admin.html", form=form)


# Send reset password link route
@admin_control_bp.route("/2/send_password_link", methods=['GET'])
def send_password_link():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    # Check whether admin_id in session
    no_admin_id = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admin_details',
        flash_message='There is no admin selected to unlock. Please choose an admin account to unlock.',
        log_message='User tried to unlock an admin account without provided the account id',
        keys_to_keep=ADMIN_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_admin_id:
        return no_admin_id

    # Check whether account actually exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the admin account to unlock", "error")
        logger.error(f"User tried to unlock an admin without providing the id for an existing account")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    # Check whether account is not locked
    locked_account = LockedAccount.query.get(admin_id)
    if locked_account:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("You cannot send a password reset link to a locked admin account.", "error")
        logger.error(f"User tried to send password reset link for locked admin account '{admin.username}'.")
        return redirect(url_for("admin_control_bp.view_admin_details"))

    # Generate secure token for password reset
    email = admin.email
    token = PasswordResetToken.create(email=email)
    reset_url = url_for('recovery_auth_bp.reset_password', token=token, _external=True)

    # Try sending email using utility send_email function
    email_body = f'Click the link to reset your password: <a href="{reset_url}" rel="noreferrer">{reset_url}</a>'
    if send_email(email, "Password Reset Request", email_body):
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for("admin_control_bp.view_admin_details"))
        unset_jwt_cookies(response)
        flash("A password reset link has been sent!", "success")
        logger.info(f"Password reset link sent to {email}")
        return response
    else:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("An error occurred while sending the password reset link. Please try again.", "error")
        logger.error(f"Failed to send password reset link to {email}")
        return redirect(url_for("admin_control_bp.view_admin_details"))


# Re-generate admin key route
@admin_control_bp.route("/2/generate_admin_key", methods=['GET'])
def generate_admin_key():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    # Check whether admin_id in session
    no_admin_id = check_session_keys(
        required_keys=['admin_id'],
        fallback_endpoint='admin_control_bp.view_admin_details',
        flash_message='There is no admin selected to unlock. Please choose an admin account to unlock.',
        log_message='User tried to unlock an admin account without provided the account id',
        keys_to_keep=ADMIN_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_admin_id:
        return no_admin_id

    # Check whether account actually exists
    admin_id = session.get("admin_id")
    admin = Admin.query.get(admin_id)
    if not admin:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the admin account to unlock", "error")
        logger.error(f"User tried to unlock an admin without providing the id for an existing account")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    # Check whether account is not locked
    locked_account = LockedAccount.query.get(admin_id)
    if locked_account:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("You cannot generate a new key for a locked admin account.", "error")
        logger.error(f"User tried to regenerate admin key for locked admin account '{admin.username}'.")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    
    # Generate a new admin key & try to send email
    admin_key = admin.generate_admin_key()
    email_body = f"A new admin key has been generated: {admin_key}. Use this to perform administrative actions."
    if send_email(admin.email, "New Admin Key", email_body):
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("Successfully generated a new admin key!", "success")
        logger.info(f"Successfully generated a new admin key for admin account '{admin.username}'")
        return redirect(url_for("admin_control_bp.view_admin_details"))
    else:
        clear_unwanted_session_keys(ADMIN_SPECIFIC_ESSENTIAL_KEYS)
        flash("An error occurred while generating a new admin key.")
        logger.error(f"Failed to send email to inform admin '{admin.username}' that a new admin key was generated.")
        return redirect(url_for("admin_control_bp.view_admin_details"))


# Admin creation route for creating new admins (requires 2FA with OTP sent to email)
@admin_control_bp.route("/3", methods=['GET', 'POST'])
def create_admin():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks()
    if check_result:
        return check_result
    
    form = CreateAdminForm()
    if request.method == "POST" and form.validate_on_submit():
        # Clean inputs
        username = clean_input(form.username.data)
        email = clean_input(form.email.data)
        password = clean_input(form.password.data)
        password_hash = generate_password_hash(password)

        # Create JWT token for sensitive data
        identity = {'email': email, 'username': username, 'password_hash': password_hash}
        token = create_access_token(identity=identity)
        response = redirect(url_for('admin_control_bp.send_otp'))
        set_access_cookies(response, token)

        # Store intermediate stage in session
        session['create_admin_stage'] = 'send_otp'
        return response

    return render_template(f"{TEMPLATE_FOLDER}/create_admin.html", form=form)


# Send otp route
@admin_control_bp.route('/3/send_otp', methods=["GET"])
@jwt_required()
def send_otp():
    # Conduct essential checks to manage access control
    check_result = admin_control_checks(ESSENTIAL_KEYS)
    if check_result:
        return check_result

    # Check whether signup stage correct (create_admin_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="create_admin_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='admin_control_bp.create_admin',
        flash_message="Your session has expired. Please re-authenticate with a valid master key.",
        log_message="Invalid admin creation stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has username, email
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email', 'password_hash'],
        required_claims=None,
        fallback_endpoint='admin_control_bp.create_admin',
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt

    # Generate otp
    identity = get_jwt_identity()
    otp = generate_otp()
    hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    otp_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()  # OTP valid for 5 minutes
    otp_data = {'otp': hashed_otp, 'expiry': otp_expiry}

    # Update JWT token with OTP and expiry
    new_token = create_access_token(identity=identity, additional_claims={"otp_data": otp_data})
    response = redirect(url_for('admin_control_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = f"Your OTP is {otp}. It will expire in 5 minutes."
    create_admin_stage = session.get("create_admin_stage")
    if send_email(identity['email'], "Your OTP Code", email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['email']}"

        if create_admin_stage == 'send_otp':
            session["create_admin_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and create_admin_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif create_admin_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['email']}"
        
        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if create_admin_stage == "send_otp":
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            response = redirect(url_for("admin_control_bp.create_admin"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['email']}")

    # Redirect to verify email
    return response


# Verify email route
@admin_control_bp.route("/3/verify_email", methods=["GET", "POST"])
@jwt_required()
def verify_email():
    # Redirect to create admin & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = redirect(url_for('admin_control_bp.create_admin'))
        unset_jwt_cookies(response)
        flash("Admin creation process restarted.", "info")
        logger.info("User opted to restart the admin creation process.")
        return response

    # Check whether signup stage correct (create_admin_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="create_admin_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='admin_control_bp.create_admin',
        flash_message="Your session has expired. Please re-authenticate with a valid master key.",
        log_message="Invalid admin creation stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has username, email & jwt claims has otp_data
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email', 'password_hash'],
        required_claims=['otp_data'],
        fallback_endpoint='admin_control_bp.create_admin',
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt

    # Check whether otp_data expired
    jwt = get_jwt()
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('admin_control_bp.send_otp', expired_otp=True))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input == actual otp stored in jwt
        if hashed_user_otp == otp_data['otp']:
            # Create new admin based on jwt identity
            identity = get_jwt_identity()
            new_admin = Admin.create(username=identity['username'], email=identity['email'], password_hash=identity['password_hash'])
            db.session.add(new_admin)
            db.session.commit()

            # Clear JWT & session data
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            response = redirect(url_for("admin_control_bp.view_admins"))
            flash("Email verified successfuly. New admin account created!", "success")
            logger.info(f"New admin account with username '{identity['username']}' created succesfully!")

            return response
        else:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['email']}")

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form, otp_expiry=otp_expiry)
