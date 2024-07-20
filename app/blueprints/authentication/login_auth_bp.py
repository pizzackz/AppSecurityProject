import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import Blueprint, request, session, redirect, render_template, flash, url_for
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from flask_login import login_user
from werkzeug.security import check_password_hash
from typing import Union

from app import db, login_manager
from app.models import User, Member, Admin
from app.forms.auth_forms import LoginForm, OtpForm
from app.utils import clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_auth_stage, check_jwt_values


login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__, url_prefix="/login")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER = "authentication/login"
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)
LOCKED_REASON = "Too many failed login attempts"


# User loader function to retrieve user object from database
@login_manager.user_loader
def load_user(user_id: int) -> Union[User, Member, Admin]:
    user_id = int(user_id)
    user: User = User.query.get(user_id)

    if user:
        if user.type == "member":
            return Member.query.get(user_id)
        elif user.type == "admin":
            return Admin.query.get(user_id)
    return user


# Initial login route
@login_auth_bp.route("/", methods=['GET', 'POST'])
def login():
    """
    Login route to initiate the login process.
    It validates the login form, cleans inputs and stores intermediate stage in session.
    """
    # Clear session keys that are not needed
    clear_unwanted_session_keys()

    form = LoginForm()
    
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & clean inputs
        username = clean_input(form.username.data)
        password = form.password.data

        # Check if account exists
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Invalid username or password. Please try again.", "error")
            logger.warning(f"Login attempt with non-existent username: {username}")
            return redirect(url_for("login_auth_bp.login"))

        # Check if account locked
        if user.account_status.is_locked and user.account_status.lockout_time > datetime.now(timezone.utc):
            flash(f"Your account is locked: {user.locked_account.locked_reason}. Please try again later.", "error")
            logger.warning(f"User with username '{username}' tried logging in into a locked account.")
            return redirect(url_for("login_auth_bp.login"))

        # Check input password not match stored password
        if not check_password_hash(user.password_hash, password):
            account_status = user.increment_failed_attempts()

            # Lock account if failed_attempts > max_attempts
            if account_status.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.lock_account(locked_reason=LOCKED_REASON, lockout_duration=LOCKOUT_DURATION)
                flash("Your account is locked due to too many failed login attempts. Please try again later.", "error")
                logger.warning(f"User with username '{username}' tried logging in into a locked account.")
                return redirect(url_for("login_auth_bp.login"))

            flash("Invalid username or password. Please try again.", "error")
            logger.warning(f"Incorrect password attempt for username: {username}")
            return redirect(url_for("login_auth_bp.login"))
        
        # Reset failed login attempts on correct username & password
        user.reset_failed_attempts()

        # Create JWT token for sensitive data
        response = redirect(url_for('login_auth_bp.send_otp'))
        identity = {'username': user.username, 'email': user.email}
        token = create_access_token(identity=identity)
        set_access_cookies(response, token)

        # Store intermediate stage in session
        session['login_stage'] = 'send_otp'

        # Redirect to send_otp
        return response
    
    # Render the base login template
    return render_template(f"{TEMPLATE_FOLDER}/login.html", form=form)


# Send otp route
@login_auth_bp.route('/send_otp', methods=['GET'])
@jwt_required()
def send_otp():
    # Check if the session is expired
    if 'login_stage' not in session:
        flash("Your session has expired. Please restart the login process.", "error")
        logger.error(f"Session expired")
        return redirect(url_for('login_auth_bp.login'))

    # Check whether auth stage correct (login_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="login_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process.",
        log_message="Invalid login stage"
    )
    if check:
        return check

    # Check jwt identity has username, email
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=None,
        fallback_endpoint='login_auth_bp.login'
    )
    if check_jwt:
        return check_jwt

    # Generate otp
    identity = get_jwt_identity()
    otp = generate_otp()
    hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    otp_expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()  # OTP valid for 10 minutes
    otp_data = {'otp': hashed_otp, 'expiry': otp_expiry}

    # Update JWT token with OTP and expiry
    new_token = create_access_token(identity=identity, additional_claims={"otp_data": otp_data})
    response = redirect(url_for('login_auth_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = f"Your OTP is {otp}. It will expire in 10 minutes."
    login_stage = session.get("login_stage")
    if send_email(identity['email'], "Your OTP Code", email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['email']}"

        if login_stage == 'send_otp':
            session["login_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and login_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif login_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['email']}"

        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if login_stage == "send_otp":
            session.clear()
            response = redirect(url_for("login_auth_bp.login"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['email']}")

    # Redirect to verify email
    return response


# Verify email route
@login_auth_bp.route("/verify_email", methods=["GET", "POST"])
@jwt_required()
def verify_email():
    # Redirect to signup & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('login_auth_bp.login'))
        unset_jwt_cookies(response)
        flash("Login process restarted.", "info")
        logger.info("User opted to restart the login process.")
        return response

    # Check session not expired & signup_stage == verify_email
    check = check_auth_stage(
        auth_process="login_stage",
        allowed_stages=['verify_email'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process.",
        log_message="Invalid login stage"
    )
    if check:
        return check

    # Check jwt identity has username, email & jwt claims has otp_data
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=['otp_data'],
        fallback_endpoint='login_auth_bp.login'
    )
    if check_jwt:
        return check_jwt

    # Check whether otp_data expired
    jwt = get_jwt()
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('login_auth_bp.send_otp', expired_otp=True))
    
    # Check if the uer account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(username=identity['username'], email=identity['email']).first()
    if not user:
        flash("An error occurred. Please restart the login process.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('login_auth_bp.login'))

    # Check if account locked
    if user.account_status.is_locked and user.account_status.lockout_time > datetime.now(timezone.utc):
        flash("Your account is currently locked. Please try again later.", "error")
        logger.warning(f"User with username '{identity['username']}' tried logging in into a locked account.")
        return redirect(url_for("login_auth_bp.login"))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input otp == actual otp stored in jwt
        if not hashed_user_otp == otp_data['otp']:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['username']}")
            return redirect(url_for("login_auth_bp.verify_email"))

        # Get correct endpoint based on user type
        user = User.query.filter_by(username=identity['username'], email=identity['email']).first()
        type = user.type
        endpoint = "login_auth_bp.login"
        # if type == "member": endpoint = "member_auth_bp.home"
        # elif type == "admin": endpoint = "admin_auth_bp.home"
        
        # Clear any jwt & session data, Log user in
        session.clear()
        response = redirect(url_for(endpoint))
        unset_jwt_cookies(response)
        login_user(user)

        # Display messages
        flash("Email verified successfully. You are now logged in.", "success")
        logger.info(f"Email verified for user - '{identity['username']}' and user is logged in")
        
        print(session)
        return response

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form)

