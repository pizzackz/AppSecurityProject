import logging
import hashlib
import uuid
import os

from datetime import datetime, timedelta, timezone
from logging import Logger

from flask import Blueprint, request, session, redirect, render_template, flash, url_for, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.models import User, Member, ProfileImage
from app.forms.profile_forms import MemberProfileForm
from app.forms.auth_forms import OtpForm, ResetPasswordForm, PasswordForm
from app.utils import clean_input, generate_otp, send_email, check_auth_stage, check_jwt_values, check_member, clear_unwanted_session_keys, get_image_url, upload_pfp, reset_pfp


member_profile_bp: Blueprint = Blueprint("member_profile_bp", __name__, url_prefix="/profile")
logger: Logger = logging.getLogger('tastefully')

# Initialise variables
TEMPLATE_FOLDER = "member/profile"
ESSENTIAL_KEYS = {'_user_id', '_fresh', '_id'}


# Base profile route
@member_profile_bp.route("/", methods=['GET', 'POST'])
@login_required
def profile():
    clear_unwanted_session_keys(ESSENTIAL_KEYS)

    # Check if user is member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    
    action = request.form.get("action", None) or request.args.get("action", None)
    print(f"action = {action}")

    # Fetch complete user data from the database
    user = Member.query.filter_by(id=current_user.id).first()

    # Check if user doesn't exist
    if not user:
        flash("An unexpected error occurred. Please log in again.", "error")
        logger.warning(f"Anonymous user tried entering member profile page without an existing user id")
        return redirect(url_for('login_auth_bp.login'))

    # Redirect to allow reset of password or setting of password (for google sign-in users)
    if action in ("reset_password", "set_password"):
        session['profile_update_stage'] = 'send_otp'
        update_option = ""

        if action == "reset_password":
            update_option = 'reset_password'
        if action == "set_password":
            update_option = 'set_password'

        # Store jwt data
        response = redirect(url_for('member_profile_bp.send_otp'))
        identity = {'email': user.email}
        token = create_access_token(identity=identity, additional_claims={"update_option": update_option})
        set_access_cookies(response, token)

        return response

    # Remove google_id when user clicked on unlink account
    if action == "unlink_account" and user.google_id:
        try:
            user.google_id = None
            user.profile_images.google_url = None
            user.profile_images.source = "file_system"
            db.session.commit()
            flash("Successfully unlinked your Google account!", "success")
            logger.info(f"User '{user.username}' successfully unlinked their Google account.")
        except Exception as e:
            db.session.clear()
            flash("An error occurred while trying to unlink your Google account. Please try again later.", "error")
            logger.error(f"Unsuccessful unlinking user '{user.username}' from their Google account: {e}")

        return redirect(url_for("member_profile_bp.profile"))

    # Redirect to handle subscrition plan actions (upgrade to premium, renew premium)
    if action in ("renew_plan", "upgrade_plan"):
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        endpoint = "member_subscription_bp.plan_select"

        if action == "renew_plan":
            response = redirect(url_for(endpoint, action="renew_plan"))
        elif action == "upgrade_plan":
            response = redirect(url_for(endpoint, action="upgrade_plan"))
        else:
            response = redirect(url_for(endpoint, action="cancel_plan"))

        return response
    
    # Handle proper cancellation of premium subscription plan
    if action == "cancel_plan":
        try:
            user.subscription_plan = "standard"
            user.subscription_end_date = None
            db.session.commit()

            flash("Your subscription has successfully been cancelled!", "success")
            logger.info(f"User '{user.username}' has successfully cancelled their subscription.")
        except Exception as e:
            flash("An erorr occurred while trying to cancel your subscription. Please try again later.", "error")
            logger.error(f"Error tring to cancel subscription for user '{user.username}': {e}")
        return redirect(url_for("member_profile_bp"))

    form = MemberProfileForm()
    
    # Force refresh if clicked on 'revert'
    if request.method == "POST" and action == "revert":
        flash("All changes made were reverted!", "success")
        logger.info(f"User '{user.username}' reverted profile details changes.")
        return redirect(url_for("member_profile_bp.profile"))

    # Handle profile picture upload/ reset
    if request.method == "POST" and action in ("upload_profile_picture", "reset_profile_picture") and form.validate_on_submit():
        # Check if user has linked to Google
        if user.google_id:
            flash("Your profile picture cannot be removed since you are linked to Google.", "info")
            logger.info(f"User '{user.username}' tried to update their profile picture despite being linked to google.")
            return redirect(url_for("member_profile_bp.profile"))
        
        profile_image = ProfileImage.query.get(user.id)
        # Check if profile image record exists
        if not profile_image:
            flash("An error occurred. Please try again later.", "error")
            logger.error(f"Couldn't find profile image record for '{user.username}'.")
            return redirect(url_for('member_profile_bp.profile'))

        # Call appropriate functions
        if action == "upload_profile_picture":
            return upload_pfp(user, profile_image, form.profile_picture.data, "member_profile_bp.profile")
        elif action == "reset_profile_picture":
            return reset_pfp(user, profile_image, "member_profile_bp.profile")

    # Basic form detail submission
    if request.method == "POST" and action == "next" and form.validate_on_submit():
        flash_message_parts = []
        log_message_parts = []

        # Check if email was attempted to be changed
        if form.email.data and clean_input(form.email.data) != user.email:
            flash_message_parts.append("email")
            log_message_parts.append("email")

        # Check if a Google-linked user attempted to change their username
        if user.google_id and form.username.data and (clean_input(form.username.data) != user.username):
            flash_message_parts.append("username")
            log_message_parts.append("username")

        # If there are any restricted updates, show messages and log the attempt
        if flash_message_parts:
            flash_message = "You are not allowed to update your " + " and ".join(flash_message_parts) + "!"
            log_message = f"User '{user.username}' tried to update their " + " and ".join(log_message_parts)

            flash(flash_message, "error")
            logger.warning(log_message)
            return redirect(url_for("member_profile_bp.profile"))

        # Retrieve inputs
        username = form.username.data
        phone_number = form.phone_number.data
        address = form.address.data
        postal_code = form.postal_code.data

        # Check whether there's actually data to update
        changed_username = not user.google_id and username != user.username
        changed_phone_number = phone_number and phone_number != user.phone_number
        changed_address = address and address != user.address
        changed_postal_code = postal_code and postal_code != user.postal_code

        # Clean & store any updated data
        updated_data = {}
        if changed_username:
            # Check for unique username
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash("Username is already in use. Please choose another one.", "error")
                logger.warning(f"User '{user.username}' tried to update their username to an existing username '{username}'.")
                return redirect(url_for("member_profile_bp.profile"))
            else:
                updated_data['username'] = clean_input(username)
        if changed_phone_number:
            updated_data['phone_number'] = clean_input(phone_number)
        if changed_address:
            updated_data['address'] = clean_input(address)
        if changed_postal_code:
            updated_data['postal_code'] = clean_input(postal_code)

        if not updated_data:
            flash("Please update at least one of the fields to proceed.", "info")
            logger.info(f"User '{current_user.username}' tried to submit empty form when updating profile")
            return redirect(url_for("member_profile_bp.profile"))

        # Store data in jwt
        response = redirect(url_for('member_profile_bp.send_otp'))
        identity = {'email': user.email}
        claims = {"updated_data": updated_data, "update_option": "basic"}
        token = create_access_token(identity=identity, additional_claims=claims)
        set_access_cookies(response, token)

        # Set profile update stage in session
        session['profile_update_stage'] = 'send_otp'

        # Redirect to send OTP page
        return response

    image_url = get_image_url(user)

    # Render the base member profile template
    return render_template(f"{TEMPLATE_FOLDER}/profile.html", form=form, user=user, image=image_url)


# Send otp route
@member_profile_bp.route("/send_otp", methods=['GET'])
@jwt_required()
@login_required
def send_otp():
    # Check if the user is a member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check if the session is expired
    if 'profile_update_stage' not in session:
        flash("Your session has expired. Please try again.", "error")
        logger.error(f"Session expired")
        return redirect(url_for('member_profile_bp.profile'))

    # Check whether auth stage correct (profile_update_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="profile_update_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="Your session has expired. Please try again.",
        log_message="Invalid profile update stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has email and jwt claims has update_option
    check_jwt = check_jwt_values(
        required_identity_keys=['email'],
        required_claims=["update_option"],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="An error occurred. Please try again later.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt

    # Check jwt claims for allowed update_options
    jwt = get_jwt()
    update_option = jwt.get("update_option")
    allowed_options = ('basic', 'set_password', 'reset_password', 'change_profile_picture')
    if update_option not in allowed_options:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"Attempted to verify email without allowed update option. Update option = '{update_option}'")
        return response
    
    # Check jwt update_option is 'basic' if have updated_data
    updated_data = jwt.get("updated_data")
    if update_option == "basic" and not updated_data:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"Attempted to verify email to update basic data without updated data.")
        return response

    identity = get_jwt_identity()

    # Generate otp
    otp = generate_otp()
    hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    otp_expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()  # OTP valid for 10 minutes
    otp_data = {'otp': hashed_otp, 'expiry': otp_expiry}

    # Update JWT token with OTP and expiry
    claims = {"otp_data": otp_data, "updated_data": updated_data, "update_option": update_option}
    new_token = create_access_token(identity=identity, additional_claims=claims)
    response = redirect(url_for('member_profile_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = f"Your OTP is {otp}. It will expire in 10 minutes."
    profile_update_stage = session.get("profile_update_stage")
    if send_email(identity['email'], "Your OTP Code", email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['email']}"

        if profile_update_stage == 'send_otp':
            session["profile_update_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and profile_update_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif profile_update_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['email']}"

        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if profile_update_stage == "send_otp":
            session.clear()
            response = redirect(url_for("login_auth_bp.login"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['email']}")

    # Redirect to verify email
    return response


# Verify email route
@member_profile_bp.route("/verify_email", methods=["GET", "POST"])
@jwt_required()
@login_required
def verify_email():
    # Check if the user is a member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Redirect to profile & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.pop("profile_update_stage", None)
        response = redirect(url_for('member_profile_bp.profile'))
        unset_jwt_cookies(response)
        flash("Profile details update canceled.", "info")
        logger.info("User opted to cancel the profile details update process.")
        return response

    # Check session not expired & profile_update_stage == verify_email
    check = check_auth_stage(
        auth_process="profile_update_stage",
        allowed_stages=['verify_email'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="Your session has expired. Please try again.",
        log_message="Invalid profile update stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has email & jwt claims has otp_data, update_option
    check_jwt = check_jwt_values(
        required_identity_keys=['email'],
        required_claims=['otp_data', 'update_option'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="An error occurred. Please try again later.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt

    # Check jwt claims for allowed update_options
    jwt = get_jwt()
    update_option = jwt.get("update_option")
    allowed_options = ('basic', 'set_password', 'reset_password', 'change_profile_picture')
    if update_option not in allowed_options:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"Attempted to verify email without allowed update option. Update option = '{update_option}'")
        return response
    
    # Check jwt update_option is 'basic' if have updated_data
    updated_data = jwt.get("updated_data")
    if update_option == "basic" and not updated_data:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"Attempted to verify email to update basic data without updated data.")
        return response
    
    # Check whether otp_data expired
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('member_profile_bp.send_otp', expired_otp=True))
    
    # Check if the user account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(id=current_user.id, email=identity['email']).first()
    if not user:
        flash("An error occurred. Please try updating your details again.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('member_profile_bp.profile'))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input otp == actual otp stored in jwt
        if hashed_user_otp != otp_data['otp']:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {user.username}")
            return redirect(url_for("member_profile_bp.verify_email"))
        
        # Prepare for redirection based on update_option
        # Retrieving and updating jwt identity and additional claims
        identity['email_verified'] = True
        claims = {'update_option': update_option}
        response = redirect(url_for("member_profile_bp.save_changes"))

        # Saving update stage according to update option
        if update_option == "basic":
            session['profile_update_stage'] = 'save_changes'
            claims['updated_data'] = updated_data
        elif update_option == "set_password":
            session['profile_update_stage'] = 'set_password'
            response = redirect(url_for("member_profile_bp.set_password"))
        elif update_option == "reset_password":
            session['profile_update_stage'] = 'reset_password'
            response = redirect(url_for("member_profile_bp.reset_password"))
        elif update_option == "change_profile_picture":
            session['profile_update_stage'] = 'change_profile_picture'
            response = redirect(url_for("member_profile_bp.change_profile_picture"))
        
        # Set jwt token & redirect
        new_token = create_access_token(identity=identity, additional_claims=claims)
        set_access_cookies(response, new_token)
        return response

    image_url = get_image_url(user)

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form, user=user, image=image_url)


# Save (basic) changes route
@member_profile_bp.route("/save_changes", methods=['GET'])
@jwt_required()
@login_required
def save_changes():
    # Check if the user is a member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check session not expired & profile_update_stage == save_changes
    check = check_auth_stage(
        auth_process="profile_update_stage",
        allowed_stages=['save_changes'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="Your session has expired. Please try again.",
        log_message="Invalid profile update stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has email & email_verified & jwt claims has updated_data, update_option
    check_jwt = check_jwt_values(
        required_identity_keys=['email', 'email_verified'],
        required_claims=['updated_data', 'update_option'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="An error occurred. Please try again later.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt
    
    # Check update_option is 'basic'
    jwt = get_jwt()
    update_option = jwt.get("update_option")
    if update_option != 'basic':
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"User {current_user.username}' attempted to save basic profile changes with incorrect update option '{update_option}'.")
        return response
        
    # Check if the user account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(id=current_user.id, email=identity['email']).first()
    if not user:
        flash("An error occurred. Please try updating your details again.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('member_profile_bp.profile'))
    
    # Update user data according to data in jwt claims
    updated_data = jwt.get("updated_data", {})

    try:
        flash_message = ["Email verified successfully. Your changes have been saved!", "success"]
        log_message = [f"Email verified for user '{user.username}' and profile changes have been saved", "info"]

        # Update the user object with the new data
        if 'username' in updated_data:
            user.username = updated_data['username']
        if 'phone_number' in updated_data:
            user.phone_number = updated_data['phone_number']
        if 'address' in updated_data:
            user.address = updated_data['address']
        if 'postal_code' in updated_data:
            user.postal_code = updated_data['postal_code']
        
        user.updated_at = datetime.now(timezone.utc).isoformat()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash_message = ["An error occurred while updating your profile. Please try again later.", "error"]
        log_message = [f"Error updating profile for user '{user.username}': {e}", "error"]

    # Clear member update stage data & jwt data, redirect back to member profile
    session.pop("profile_update_stage")
    response = redirect(url_for('member_profile_bp.profile'))
    unset_jwt_cookies(response)
    
    # Display messages
    flash(flash_message[0], flash_message[1])
    if log_message[1] == "info":
        logger.info(log_message[0])
    elif log_message[1] == "error":
        logger.error(log_message[0])

    return response


# Set password route - For users who logged in via Google Sign-in without passwords
@member_profile_bp.route("/set_password", methods=['GET', 'POST'])
@jwt_required()
@login_required
def set_password():
    # Check if user is member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Redirect to profile & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.pop("profile_update_stage", None)
        response = redirect(url_for('member_profile_bp.profile'))
        unset_jwt_cookies(response)
        flash("Setting of password canceled.", "info")
        logger.info("User opted to restart cancel password setting.")
        return response

    # Check session not expired & profile_update_stage == save_changes
    check = check_auth_stage(
        auth_process="profile_update_stage",
        allowed_stages=['set_password'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="Your session has expired. Please try again.",
        log_message="Invalid profile update stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has email & jwt claims has update_option
    check_jwt = check_jwt_values(
        required_identity_keys=['email', 'email_verified'],
        required_claims=['update_option'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="An error occurred. Please try again later.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt
    
    # Check update_option is 'reset_password'
    jwt = get_jwt()
    update_option = jwt.get("update_option")
    if update_option != 'set_password':
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"User {current_user.username}' attempted to set their password with incorrect update option '{update_option}'.")
        return response
        
    # Check if the user account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(id=current_user.id, email=identity['email']).first()
    if not user:
        flash("An error occurred. Please try setting your password again.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('member_profile_bp.profile'))
    
    form = PasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve inputted password
        password = form.password.data

        # Check if inputted password same as current password
        if user.password_hash and check_password_hash(user.password_hash, password):
            flash("The new password cannot be the same as your current password. Please choose a different password.", "error")
            logger.warning(f"User {user.email} attempted to reuse their current password when resetting.")
            return redirect(url_for('member_profile_bp.set_password'))
        
        # Update user's password
        try:
            flash_message = ["You have successfully set your password!", "success"]
            log_message = [f"Password successfully set for user: {user.username}", "info"]
            user.password_hash = generate_password_hash(password)
            user.updated_at = datetime.now(timezone.utc).isoformat()
            db.session.commit()
        except Exception as e:
            flash_message = ["An error occurred when saving your password. Please try again later", "error"]
            log_message = [f"Error saving password for user '{user.username}': {e}", "error"]
        
        # Clear member update stage data & jwt data, redirect back to member profile
        session.pop("profile_update_stage")
        response = redirect(url_for('member_profile_bp.profile'))
        unset_jwt_cookies(response)

        # Display messages
        flash(flash_message[0], flash_message[1])
        if log_message[1] == "info":
            logger.info(log_message[0])
        else:
            logger.error(log_message[0])
        
        return response

    image_url = get_image_url(user)

    # Render the set password template
    return render_template(f"{TEMPLATE_FOLDER}/set_password.html", form=form, user=user, image=image_url)


# Reset password route
@member_profile_bp.route("/reset_password", methods=['GET', 'POST'])
@jwt_required()
@login_required
def reset_password():
    # Check if user is member
    check = check_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Redirect to profile & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.pop("profile_update_stage", None)
        response = redirect(url_for('member_profile_bp.profile'))
        unset_jwt_cookies(response)
        flash("Password reset canceled.", "info")
        logger.info("User opted to restart cancel password reset.")
        return response

    # Check session not expired & profile_update_stage == save_changes
    check = check_auth_stage(
        auth_process="profile_update_stage",
        allowed_stages=['reset_password'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="Your session has expired. Please try again.",
        log_message="Invalid profile update stage",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check:
        return check

    # Check jwt identity has email & jwt claims has update_option
    check_jwt = check_jwt_values(
        required_identity_keys=['email', 'email_verified'],
        required_claims=['update_option'],
        fallback_endpoint='member_profile_bp.profile',
        flash_message="An error occurred. Please try again later.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if check_jwt:
        return check_jwt
    
    # Check update_option is 'reset_password'
    jwt = get_jwt()
    update_option = jwt.get("update_option")
    if update_option != 'reset_password':
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        response = make_response(redirect(url_for("member_profile_bp.profile")))
        unset_jwt_cookies(response)
        flash("An error occurred. Please try again later.", 'error')
        logger.error(f"User {current_user.username}' attempted to reset their password with incorrect update option '{update_option}'.")
        return response

    # Check if the user account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(id=current_user.id, email=identity['email']).first()
    if not user:
        flash("An error occurred. Please try resetting your password again.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('member_profile_bp.profile'))

    form = ResetPasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve inputted passwords
        curr_password = form.curr_password.data
        new_password = form.new_password.data

        # Check if curr_password inputted same as current password
        if not check_password_hash(user.password_hash, curr_password):
            flash("The current password you entered is incorrect. Please try again.", "error")
            logger.warning(f"User {user.email} entered an incorrect current password")
            return redirect(url_for('member_profile_bp.reset_password'))

        # Check if the new password is the same as the current password
        if check_password_hash(user.password_hash, new_password):
            flash("Your new password cannot be the same as your current password.", "error")
            logger.warning(f"User {user.username} attempted to set the same password as the current one")
            return redirect(url_for('member_profile_bp.reset_password'))

        # Update user's password
        try:
            flash_message = ["Your password has been reset successfully!", "success"]
            log_message = [f"Password reset successfully for user: {user.username}", "info"]
            user.password_hash = generate_password_hash(new_password)
            user.updated_at = datetime.now(timezone.utc).isoformat()
            db.session.commit()
        except Exception as e:
            flash_message = ["An error occurred when resetting your password. Please try again later", "error"]
            log_message = [f"Error saving password for user '{user.username}' when resetting it: {e}", "error"]
        
        # Clear member update stage data & jwt data, redirect back to member profile
        session.pop("profile_update_stage")
        response = redirect(url_for('member_profile_bp.profile'))
        unset_jwt_cookies(response)

        # Display messages
        flash(flash_message[0], flash_message[1])
        if log_message[1] == "info":
            logger.info(log_message[0])
        else:
            logger.error(log_message[0])

        return response

    image_url = get_image_url(user)

    # Render the reset password template
    return render_template(f"{TEMPLATE_FOLDER}/reset_password.html", form=form, user=user, image=image_url)

