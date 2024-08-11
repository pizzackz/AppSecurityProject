import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import Blueprint, request, redirect, render_template, url_for, flash, session
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from flask_limiter import RateLimitExceeded
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, limiter
from app.models import User, LockedAccount, PasswordResetToken
from app.forms.auth_forms import EmailForm, OtpForm, RecoverOptionsForm, ResetPasswordForm
from app.utils import invalidate_user_sessions, logout_if_logged_in, clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_auth_stage, check_jwt_values


# Initialise flask blueprint - 'login_aut_bp'
recovery_auth_bp: Blueprint = Blueprint("recovery_auth_bp", __name__, url_prefix="/recovery")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER = "authentication/recovery"


# Account recovery specific rate exceedance handler
@recovery_auth_bp.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    # Log the rate limit exceedance for the specific blueprint
    logger.warning(f"Rate limit exceeded for {request.endpoint} in recovery_auth_bp")

    match request.endpoint:
        case 'recovery_auth_bp.recovery':
            flash("Too many recovery attempts. Please wait a moment before trying again.", "error")
            logger.warning(f"User exceeded rate limit on recovery route.")
            return redirect(url_for("general_bp.home"))
        case 'recovery_auth_bp.send_otp':
            flash("Too many OTP requests. Please wait a moment before trying again.", "error")
            logger.warning(f"User exceeded rate limit on send OTP route.")
        case 'recovery_auth_bp.verify_email':
            flash("Too many OTP verification attempts. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on verify email route.")
        case 'recovery_auth_bp.send_username':
            flash("Too many attempts to send username. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on send username route.")
        case 'recovery_auth_bp.send_password_link':
            flash("Too many attempts to send password reset link. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on send password link route.")
        case 'recovery_auth_bp.reset_password':
            flash("Too many password reset attempts. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on reset password route.")
        case 'recovery_auth_bp.recovery_options':
            flash("Too many recovery options attempts. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on recovery options route.")
        case 'recovery_auth_bp.recover_username':
            flash("Too many attempts to recover username. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on recover username route.")
        case 'recovery_auth_bp.reset_success':
            flash("Too many attempts to view the reset success page. Please wait before trying again.", "error")
            logger.warning(f"User exceeded rate limit on reset success route.")
        case _:
            flash("You have exceeded the rate limit. Please wait a moment before trying again.", "error")
            logger.warning(f"User exceeded rate limit on an unidentified route.")

    # Redirect to the recovery page as a fallback
    return redirect(url_for("recovery_auth_bp.recovery"))


# Recovery route - Phase 1
@recovery_auth_bp.route("/", methods=['GET', 'POST'])
@limiter.limit("3 per hour")
@logout_if_logged_in
def recovery():
    """
    Recovery route to initiate the account recovery process.
    It validates the email form, cleans inputs and stores intermediate stage in session.
    """
    # Clear session keys that are not needed
    clear_unwanted_session_keys()

    # Redirect to login & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('login_auth_bp.login'))
        unset_jwt_cookies(response)
        flash("Redirected back to login.", "info")
        logger.info("User opted to login.")
        return response

    form = EmailForm()

    if request.method == "POST" and form.validate_on_submit():
        # Clean input
        email = clean_input(form.email.data)

        # Check if account exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account exists with this email.", "error")
            logger.warning(f"Recovery attempt with non-existent email: {email}")
            return redirect(url_for("recovery_auth_bp.recovery"))
        
        # Check if account is locked
        if user.account_status.is_locked:
            locked_account = LockedAccount.query.filter_by(id=user.id).first()
            if locked_account:
                locked_account.unlock_request = True
                db.session.commit()
                flash("Your account is currently locked. A request to unlock your account has been sent to support. Please wait for further instructions.", "info")
                logger.info(f"Unlock request sent for locked account with email: {email}")
                return redirect(url_for('login_auth_bp.login'))
        
        # Check if account is google linked and has no password set
        if user.google_id and not user.password_hash:
            flash("Your account is linked to Google. Please recover your account via Google.", "info")
            logger.info(f"Attempted to manually recover account details for google linked account '{user.username}' without password set.")
            return redirect(url_for("login_auth_bp.login"))

        # Create JWT token for sensitive data
        response = redirect(url_for('recovery_auth_bp.send_otp'))
        identity = {'recovery_email': email}
        token = create_access_token(identity=identity)
        set_access_cookies(response, token)

        # Store intermediate stage in session
        session['recovery_stage'] = 'send_otp'

        return response

    # Render the base signup template
    return render_template(f'{TEMPLATE_FOLDER}/recovery.html', form=form)


# Send otp route - Recovery phase 2.1
@recovery_auth_bp.route('/send_otp', methods=['GET'])
@limiter.limit("3 per 10 minutes")
@jwt_required()
def send_otp():
    # Check if the session is expired
    if 'recovery_stage' not in session:
        flash("Your session has expired. Please restart the recovery process.", "error")
        logger.error(f"Session expired")
        return redirect(url_for('recovery_auth_bp.recovery'))

    # Check whether auth stage correct (recovery_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity has recovery_email
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email'],
        required_claims=None,
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt:
        return check_jwt

    # Check user exists with provided email
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity['recovery_email']).first()
    if not user:
        flash("An error occurred. Please restart the recovery process.", "error")
        logger.error(f"User account not found for email: {identity['recovery_email']}")
        return redirect(url_for('recovery_auth_bp.recovery'))

    # Generate otp
    identity = get_jwt_identity()
    otp = generate_otp()
    hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    otp_expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()  # OTP valid for 10 minutes
    otp_data = {'otp': hashed_otp, 'expiry': otp_expiry}

    # Update JWT token with OTP and expiry
    new_token = create_access_token(identity=identity, additional_claims={"otp_data": otp_data})
    response = redirect(url_for('recovery_auth_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = render_template("emails/otp_email.html", username=user.username, otp=otp)
    recovery_stage = session.get("recovery_stage")
    if send_email(identity['recovery_email'], "Your OTP Code", html_body=email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['recovery_email']}"

        if recovery_stage == 'send_otp':
            session["recovery_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and recovery_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif recovery_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['recovery_email']}"
        
        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if recovery_stage == "send_otp":
            session.clear()
            response = redirect(url_for("recovery_auth_bp.recovery"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['recovery_email']}")

    # Redirect to verify email
    return response


# Verify email route - Recovery phase 2.2
@recovery_auth_bp.route("/verify_email", methods=["GET", "POST"])
@limiter.limit("3 per 10 minutes")
@jwt_required()
def verify_email():
    # Redirect to recovery & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('recovery_auth_bp.recovery'))
        unset_jwt_cookies(response)
        flash("Recovery process restarted.", "info")
        logger.info("User opted to restart the recovery process.")
        return response

    # Check session not expired & recovery_stage == verify_email
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['verify_email'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity has email & jwt claims has otp_data
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email'],
        required_claims=['otp_data'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt:
        return check_jwt

    # Check whether otp_data expired
    jwt = get_jwt()
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('recovery_auth_bp.send_otp', expired_otp=True))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input == actual otp stored in jwt
        if hashed_user_otp == otp_data['otp']:
            # Update the JWT to clear otp_data and set email_verified flag
            response = redirect(url_for('recovery_auth_bp.recovery_options'))
            identity = get_jwt_identity()
            identity['email_verified'] = True
            new_token = create_access_token(identity=identity)
            set_access_cookies(response, new_token)

            session['recovery_stage'] = 'recovery_options'

            flash("Email verified successfully. Please select your recovery option.", "success")
            logger.info(f"Email verified for user: {identity['recovery_email']}")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['recovery_email']}")

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form)


# Recovery options route - Recovery phase 3
@recovery_auth_bp.route('/recovery_options', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
@jwt_required()
def recovery_options():
    # Redirect to recovery & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('recovery_auth_bp.recovery'))
        unset_jwt_cookies(response)
        flash("Recovery process restarted.", "info")
        logger.info("User opted to restart the recovery process.")
        return response

    # Check session not expired & recovery_stage == verify_email
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['recovery_options'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity for email & verified email
    identity = get_jwt_identity()
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt and not identity['email_verified']:
        return check_jwt
    
    form = RecoverOptionsForm()

    if request.method == "POST" and form.validate_on_submit():
        if form.recovery_option.data == 'recover_username':
            session['recovery_stage'] = 'send_username'
            return redirect(url_for('recovery_auth_bp.send_username'))
        elif form.recovery_option.data == 'reset_password':
            session['recovery_stage'] = 'send_password_link'
            return redirect(url_for('recovery_auth_bp.send_password_link'))

    # Render the recovery options template
    return render_template(f'{TEMPLATE_FOLDER}/recovery_options.html', form=form)


# Send username route
@recovery_auth_bp.route('/send_username', methods=['GET'])
@limiter.limit("3 per hour")
@jwt_required()
def send_username():
    # Check session not expired & recovery_stage == send_username
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['send_username', 'recover_username'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity for email & verified email
    identity = get_jwt_identity()
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt and not identity['email_verified']:
        return check_jwt

    # Check user exists with provided email
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity['recovery_email']).first()
    if not user:
        flash("An error occurred. Please restart the recovery process.", "error")
        logger.error(f"User account not found for email: {identity['recovery_email']}")
        return redirect(url_for('recovery_auth_bp.recovery'))
    
    # Try sending email using utility send_email function
    username = user.username
    response = redirect(url_for('recovery_auth_bp.recover_username'))
    email_body = render_template("emails/recover_username_email.html", username=username)
    recovery_stage = session.get("recovery_stage")
    if send_email(identity['recovery_email'], "Username Recovery", html_body=email_body):
        flash_msg = "Your username has been sent to your email address."
        log_msg = f"Username send to {identity['recovery_email']}"

        if recovery_stage == "send_username":
            session["recovery_stage"] = "recover_username"
        elif recovery_stage == "recover_username" and request.args.get("action") == "resend":
            flash_msg = "Your username has been re-sent to your email address."
            log_msg = f"Username re-sent to {identity['recovery_email']}"
        
        flash(flash_msg, "success")
        logger.info(log_msg)
    else:
        if recovery_stage == "send_username":
            session['recovery_stage'] = 'recovery_options'
            response = redirect(url_for('recovery_auth_bp.recovery_options'))
            unset_jwt_cookies(response)
        flash("An error occurred while sending your username. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['recovery_email']}")

    # Redirect to recover username
    return response


# Recover username route - Username successfully sent to email
@recovery_auth_bp.route("/recover_username", methods=['GET'])
@limiter.limit("3 per hour")
@jwt_required()
def recover_username():
    # Check session not expired & recovery_stage == recover_username
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['recover_username'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity for username, email & verified email
    identity = get_jwt_identity()
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt and not identity['email_verified']:
        return check_jwt

    # Redirect to send_password_link & update temp data in session when pressed 'reset password'
    if 'action' in request.args and request.args.get('action') == 'reset_password':
        # Clear session and JWT data
        session['recovery_stage'] = 'send_password_link'
        logger.info("User opted to reset password.")
        return redirect(url_for('recovery_auth_bp.send_password_link'))

    # Redirect to login & clear temp data in session & jwt when pressed 'sign in'
    if 'action' in request.args and request.args.get('action') == 'login':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('login_auth_bp.login'))
        unset_jwt_cookies(response)
        logger.info("User opted to login.")
        return response
    
    # Render the recover username template
    return render_template(f"{TEMPLATE_FOLDER}/recover_username.html")


# Send password link route
@recovery_auth_bp.route('/send_password_link', methods=['GET'])
@limiter.limit("3 per hour")
@jwt_required()
def send_password_link():
    # Check session not expired & recovery_stage == send_username
    check = check_auth_stage(
        auth_process="recovery_stage",
        allowed_stages=['send_password_link'],
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process.",
        log_message="Invalid recovery stage"
    )
    if check:
        return check

    # Check jwt identity for email & verified email
    identity = get_jwt_identity()
    check_jwt = check_jwt_values(
        required_identity_keys=['recovery_email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='recovery_auth_bp.recovery',
        flash_message="Your session has expired. Please restart the recovery process."
    )
    if check_jwt and not identity['email_verified']:
        return check_jwt

    # Check user exists with provided email
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity['recovery_email']).first()
    if not user:
        flash("An error occurred. Please restart the recovery process.", "error")
        logger.error(f"User account not found for email: {identity['recovery_email']}")
        return redirect(url_for('recovery_auth_bp.recovery'))

    # Generate secure token for password reset
    token = PasswordResetToken.create(email=user.email)
    reset_url = url_for('recovery_auth_bp.reset_password', token=token, _external=True)

    # Try sending email using utility send_email function
    email_body = render_template("emails/password_link_email.html", username=user.username, reset_url=reset_url)
    if send_email(identity['recovery_email'], "Password Reset Request", html_body=email_body):
        session.clear()
        response = redirect(url_for("login_auth_bp.login"))
        unset_jwt_cookies(response)
        flash("A password reset link has been sent to your email address.", "success")
        logger.info(f"Password reset link sent to {identity['recovery_email']}")
        return response
    else:
        flash("An error occurred while sending the password reset link. Please try again.", "error")
        logger.error(f"Failed to send password reset link to {identity['recovery_email']}")
        return redirect(url_for("recovery_auth_bp.recovery_options"))


# Reset password route
@recovery_auth_bp.route("/reset_password", methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def reset_password():
    # Check whether token for reset password exist
    token = request.args.get('token')
    if not token:
        flash("Invalid or missing token. Please try again.", "error")
        logger.error("Missing token in password reset request")
        return redirect(url_for('recovery_auth_bp.recovery'))
    
    # Hash received token & validate against database token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    recovery_token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if not recovery_token or recovery_token.expires_at.isoformat() < (datetime.now(timezone.utc)).isoformat():
        flash("The token has expired or is invalid. Please request a new password reset link.", "error")
        logger.error("Expired or invalid token in password reset request")
        return redirect(url_for('recovery_auth_bp.recovery'))
    
    # Retrieve email from token
    email = recovery_token.email

    form = ResetPasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve new password
        new_password = form.new_password.data

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("An error occurred. Please restart the recovery process.", "error")
            logger.error(f"User not found for email: {email}")
            return redirect(url_for('recovery_auth_bp.recovery'))

        # Check if the new password is the same as the current password
        if check_password_hash(user.password_hash, new_password):
            flash("Your new password cannot be the same as your current password.", "error")
            logger.warning(f"User {email} attempted to set the same password as the current one")
            return redirect(url_for('recovery_auth_bp.reset_password', token=token))

        # Update user's password
        user.password_hash = generate_password_hash(new_password)
        user.updated_at = datetime.now(timezone.utc).isoformat()
        db.session.commit()

        # Invalidate token in db by deleting it
        db.session.delete(recovery_token)
        db.session.commit()

        # Invalidate all logged in sessions except for current
        invalidate_user_sessions(user.id, False)

        flash("Your password has been reset successfully. Please log in with your new password.", "success")
        logger.info(f"Password reset successfully for user: {email}")
        return redirect(url_for('recovery_auth_bp.reset_success'))

    # Render the password reset form template
    return render_template(f'{TEMPLATE_FOLDER}/reset_password.html', form=form)


# Reset success route - Inform user password has been reset successfully
@recovery_auth_bp.route("/reset_success", methods=['GET'])
@limiter.limit("3 per hour")
def reset_success():
    return render_template(f"{TEMPLATE_FOLDER}/reset_success.html")

