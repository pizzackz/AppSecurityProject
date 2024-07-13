import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import SignupForm, OtpForm
from app.utilities.utils import clean_input, generate_otp, send_email


signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__, url_prefix="/signup")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER: str = "authentication/signup"


# initial signup route
@signup_auth_bp.route('/', methods=['GET', 'POST'])
def signup():
    """
    Signup route to initiate the user registration process.
    It validates the signup form, cleans inputs and stores intermediate stage in session.
    """
    # Clear session and JWT data
    session.clear()
    response = make_response(render_template(f'{TEMPLATE_FOLDER}/signup.html', form=SignupForm()))
    unset_jwt_cookies(response)

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

        return response  # Return the response with the cookies set

    return render_template(f'{TEMPLATE_FOLDER}/signup.html', form=form)


# Send otp route
@signup_auth_bp.route('/send_otp', methods=["GET"])
@jwt_required()
def send_otp():
    # Check whether signup stage correct (signup_stage == send_otp or verify_email)
    signup_stage = session.get('signup_stage')
    if signup_stage not in ['send_otp', 'verify_email']:
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error(f"Invalid signup stage: {signup_stage}")
        return redirect(url_for('signup_auth_bp.signup'))

    # Get the JWT identity
    identity = get_jwt_identity()
    if not identity or not isinstance(identity, dict) or 'username' not in identity or 'email' not in identity:
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error(f"Invalid token data: {identity}")
        return redirect(url_for('signup_auth_bp.signup'))

    # Generate otp
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
    if send_email(identity['email'], "Your OTP Code", email_body):
        if signup_stage == 'send_otp':
            flash("OTP has been sent to your email address.", "success")
            logger.info(f"OTP sent to {identity['email']}")
            session["signup_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and signup_stage == "verify_email":
            flash("Your OTP has expired. A new OTP has been sent to your email address.", "success")
            logger.info(f"OTP expired and re-sent to {identity['email']}")
        elif signup_stage == 'verify_email':
            flash("OTP has been re-sent to your email address.", "success")
            logger.info(f"OTP re-sent to {identity['email']}")
    else:
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
    signup_stage = session.get('signup_stage')
    if signup_stage != 'verify_email':
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error(f"Invalid signup stage: {signup_stage}")
        return redirect(url_for('signup_auth_bp.signup'))

    # Get the JWT identity
    identity = get_jwt_identity()
    jwt = get_jwt()

    # Check jwt identity has username, email
    if not identity or not isinstance(identity, dict) or 'username' not in identity or 'email' not in identity:
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error(f"Invalid token data: {identity}")
        return redirect(url_for('signup_auth_bp.signup'))

    # Check jwt has otp_data in claims
    otp_data = jwt.get('otp_data')
    if not otp_data:
        flash("An error occurred. Please restart the signup process.", "error")
        logger.error("Missing OTP data in token.")
        return redirect(url_for('signup_auth_bp.signup'))

    # Check whether otp_data expired
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
            session['signup_stage'] = 'set_password'
            logger.info(f"OTP verified for user: {identity['email']}")
            return redirect(url_for('signup_auth_bp.set_password'))
        else:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['email']}")

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form)

