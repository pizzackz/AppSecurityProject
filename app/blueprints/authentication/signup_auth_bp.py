import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import SignupForm, OtpForm, PasswordForm, ExtraInfoForm
from app.utils import clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_signup_stage, check_jwt_values


signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__, url_prefix="/signup")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER: str = "authentication/signup"


# Initial signup route
@signup_auth_bp.route('/', methods=['GET', 'POST'])
def signup():
    """
    Signup route to initiate the user registration process.
    It validates the signup form, cleans inputs and stores intermediate stage in session.
    """
    # Clear session keys that are not needed
    clear_unwanted_session_keys()

    form = SignupForm()

    if request.method == "POST" and form.validate_on_submit():
        # Clean inputs
        username = clean_input(form.username.data)
        email = clean_input(form.email.data)

        # Create JWT token for sensitive data
        response = redirect(url_for('signup_auth_bp.send_otp'))
        identity = {'email': email, 'username': username}
        token = create_access_token(identity=identity)
        set_access_cookies(response, token)

        # Store intermediate stage in session
        session['signup_stage'] = 'send_otp'

        return response

    # Render the base signup template
    return render_template(f'{TEMPLATE_FOLDER}/signup.html', form=form)


# Send otp route
@signup_auth_bp.route('/send_otp', methods=["GET"])
@jwt_required()
def send_otp():
    # Check if the session is expired
    if 'signup_stage' not in session:
        flash("Your session has expired. Please restart the signup process.", "error")
        logger.error(f"Session expired")
        return redirect(url_for('signup_auth_bp.signup'))

    # Check whether signup stage correct (signup_stage == send_otp or verify_email)
    check = check_signup_stage(
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='signup_auth_bp.signup',
        flash_message="Your session has expired. Please restart the signup process.",
        log_message="Invalid signup stage"
    )
    if check:
        return check

    # Check jwt identity has username, email
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=None,
        fallback_endpoint='signup_auth_bp.signup'
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
    response = redirect(url_for('signup_auth_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = f"Your OTP is {otp}. It will expire in 10 minutes."
    signup_stage = session.get("signup_stage")
    if send_email(identity['email'], "Your OTP Code", email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['email']}"

        if signup_stage == 'send_otp':
            session["signup_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and signup_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif signup_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['email']}"
        
        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if signup_stage == "send_otp":
            session.clear()
            response = redirect(url_for("signup_auth_bp.signup"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['email']}")

    # Redirect to verify email
    return response


# Verify email route
@signup_auth_bp.route("/verify_email", methods=["GET", "POST"])
@jwt_required()
def verify_email():
    # Redirect to signup & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('signup_auth_bp.signup'))
        unset_jwt_cookies(response)
        flash("Signup process restarted.", "info")
        logger.info("User opted to restart the signup process.")
        return response

    # Check session not expired & signup_stage == verify_email
    check = check_signup_stage(
        allowed_stages=['verify_email'],
        fallback_endpoint='signup_auth_bp.signup',
        flash_message="Your session has expired. Please restart the signup process.",
        log_message="Invalid signup stage"
    )
    if check:
        return check

    # Check jwt identity has username, email & jwt claims has otp_data
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=['otp_data'],
        fallback_endpoint='signup_auth_bp.signup'
    )
    if check_jwt:
        return check_jwt

    # Check whether otp_data expired
    jwt = get_jwt()
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('signup_auth_bp.send_otp', expired_otp=True))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input == actual otp stored in jwt
        if hashed_user_otp == otp_data['otp']:
            # Update the JWT to clear otp_data and set email_verified flag
            response = redirect(url_for('signup_auth_bp.set_password'))
            identity = get_jwt_identity()
            identity['email_verified'] = True
            new_token = create_access_token(identity=identity)
            set_access_cookies(response, new_token)

            session['signup_stage'] = 'set_password'

            flash("Email verified successfully. Please set your password.", "success")
            logger.info(f"Email verified for user: {identity['email']}")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['email']}")

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form)


# Set password route
@signup_auth_bp.route("/set_password", methods=["GET", "POST"])
@jwt_required()
def set_password():
    # Redirect to signup & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('signup_auth_bp.signup'))
        unset_jwt_cookies(response)
        flash("Signup process restarted.", "info")
        logger.info("User opted to restart the signup process.")
        return response

    # Check if the session is expired and signup_stage == set_password
    check = check_signup_stage(
        allowed_stages=['set_password'],
        fallback_endpoint='signup_auth_bp.signup',
        flash_message="Your session has expired. Please restart the signup process.",
        log_message="Invalid signup stage"
    )
    if check:
        return check

    # Check jwt identity for username, email & verified email
    identity = get_jwt_identity()
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='signup_auth_bp.signup'
    )
    if check_jwt and not identity['email_verified']:
        return check_jwt
    
    form = PasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        password = form.password.data
        hashed_password = generate_password_hash(password)  # Hash the inputted password

        # Create new member using Member.create()
        identity = get_jwt_identity()
        new_member = Member.create(username=identity['username'], email=identity['email'], password_hash=hashed_password)
        db.session.add(new_member)
        db.session.commit()

        # Update signup_stage to extra_info
        session['signup_stage'] = 'extra_info'
        flash("Password set successfully. Please provide additional information.", "success")
        logger.info(f"Password set for user: {identity['email']}")

        return redirect(url_for('signup_auth_bp.extra_info'))

    # Render the set password template
    return render_template(f'{TEMPLATE_FOLDER}/set_password.html', form=form)


# Set extra info route
@signup_auth_bp.route("/extra_info", methods=["GET", "POST"])
@jwt_required()
def extra_info():
    # Check not expired session and correct signup_stage == extra_info
    check = check_signup_stage(
        allowed_stages=['extra_info'],
        fallback_endpoint='signup_auth_bp.signup',
        flash_message="Your session has expired. Please restart the signup process.",
        log_message="Invalid signup stage"
    )
    if check:
        return check

    # Check jwt identity for username, email & verified email
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email', 'email_verified'],
        required_claims=None,
        fallback_endpoint='signup_auth_bp.signup'
    )
    if check_jwt:
        return check_jwt

    # Check if the member account exists
    identity = get_jwt_identity()
    member = Member.query.filter_by(email=identity['email']).first()
    if not member:
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error(f"Member account not found for email: {identity['email']}")
        return redirect(url_for('signup_auth_bp.signup'))

    form = ExtraInfoForm()

    if request.method == "POST" and form.validate_on_submit():
        if request.form['action'] == 'complete':

            # Update member details
            if form.phone_number.data:
                member.phone_number = clean_input(form.phone_number.data)
            if form.address.data:
                member.address = clean_input(form.address.data)
            if form.postal_code.data:
                member.postal_code = clean_input(form.postal_code.data)
            db.session.commit()

            flash("Additional information saved successfully. Your account is now complete.", "success")
            logger.info(f"Additional information saved for user: {identity['email']}")
        elif request.form['action'] == 'skip':
            flash("You have skipped adding additional information. You can update them later.", "info")
            logger.info(f"User skipped additional information: {identity['email']}")

        # Clear session and JWT cookies
        session.clear()
        response = redirect(url_for('login_auth_bp.login'))
        unset_jwt_cookies(response)

        return response

    # Render the extra info template
    return render_template(f'{TEMPLATE_FOLDER}/extra_info.html', form=form)

