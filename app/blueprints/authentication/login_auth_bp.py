import logging

from logging import Logger
from flask import Blueprint, request, session, redirect, render_template, flash, url_for
from flask_login import login_user
from typing import Union

from app import db, login_manager
from app.models import User, Member, Admin
from app.forms.auth_forms import InitialLoginForm, VerifyOtpForm
from app.utilities.utils import clean_input, generate_otp, send_otp_email, validate_otp, set_otp_session_data, check_otp_hash, clear_session_data
from app.utilities.authentication.login_utils import get_auth_by_user_id, get_user_by_username, validate_password, handle_login_error


# Initialise flask blueprint - 'login_aut_bp'
login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__, url_prefix="/login")

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "authentication/login"


# User loader function to retrieve user object from database
@login_manager.user_loader
def load_user(user_id: int) -> Union[User, Member, Admin]:
    user_id = int(user_id)
    user: User = User.query.get(user_id)

    if user.type == "member":
        return Member.query.get(user_id)
    elif user.type == "admin":
        return Admin.query.get(user_id)
    
    return user


# Initial login route
@login_auth_bp.route("/", methods=["POST", "GET"])
def login():
    """Handles the initial login process."""

    # Create form to render
    form: InitialLoginForm = InitialLoginForm()

    # Clear existing login related session data
    clear_session_data(["username", "email", "otp_data", "login_stage"])

    # Redirect to recovery if pressed 'recover'
    if request.args.get("action") == "recover":
        return redirect(url_for("recovery_auth_bp.recovery"))

    # Redirect to signup if pressed 'signup'
    if request.args.get("action") == "signup":
        return redirect(url_for("signup_auth_bp.signup"))

    # Handle POST request & validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise inputs
        username = clean_input(form.username.data)
        password = form.password.data

        try:
            # Retrieve user & related auth record
            user = get_user_by_username(username)
            auth = get_auth_by_user_id(user.id)

            # Check password correct
            validate_password(auth, password)

            # Store session data
            session.update({"username": username, "email": user.email, "login_stage": "otp"})
        except ValueError as e:
            handle_login_error(str(e))
        else:
            return redirect(url_for("login_auth_bp.send_otp"))

    return render_template(f"{TEMPLATE_FOLDER}/login.html", form=form)


# Send OTP route
@login_auth_bp.route("/send_otp", methods=["GET"])
def send_otp():
    """Send/ Resend the OTP to the user's email."""

    # Retrieve username & email from session
    username = session.get("username")
    email = session.get("email")

    # Generate OTP & store data in session
    otp = generate_otp()
    set_otp_session_data(otp)

    # Send OTP email
    if send_otp_email(email, otp):
        if request.args.get("resend"):
            flash("An OTP has been resent to your email.", "info")
        else:
            flash("An OTP has been sent to your email.", "info")
        logger.info(f"OTP sent to {email} for user {username}.")
    else:
        if request.args.get("resend"):
            flash("Failed to resend OTP. Please try again.", "error")
        else:
            flash("Failed to send OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {email} for user {username}")

    return redirect(url_for("login_auth_bp.verify_email"))


# Email verification route
@login_auth_bp.route("/verify_email", methods=["POST", "GET"])
def verify_email():
    """Verify the OTP sent to user's email."""

    # Create form to render
    form = VerifyOtpForm()

    # Redirect to login if pressed 'back'
    if request.args.get("action") == "back":
        clear_session_data(["username", "email", "otp_data", "login_stage"])
        return redirect(url_for("login_auth_bp.login"))

    # Handle POST request and validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise OTP from form, Retrieve otp_data from session
        input_otp = clean_input(form.otp.data)
        otp_data = session.get("otp_data")

        try:
            # Validate and check otp
            validate_otp(otp_data, required_keys=["value", "gen_time", "verified"])
            check_otp_hash(otp_data.get("value"), input_otp)

            # Update session otp data object
            otp_data["verified"] = True
            session.update({"otp_data": otp_data, "login_stage": "finalise_login"})
        except Exception as e:
            flash("Invalid OTP. Please try again.", "error")
            logger.error(f"Invalid email verification attempt: {e}")
        else:
            return redirect(url_for("login_auth_bp.finalise_login"))

    return render_template(f"{TEMPLATE_FOLDER}/verify_email.html", form=form)


# Finalise login route (after successful email verification)
@login_auth_bp.route("/finalise_login", methods=["GET"])
def finalise_login():
    """Finalise the login process & redirect to appropriate homepages"""
    # Retrieve username from session
    username = session.get("username")

    try:
        user = get_user_by_username(username)

        # Log in the user
        login_user(user)

        # Redirect according to the appropriate account type
        if user.type == "member":
            return redirect(url_for("member.home"))
        elif user.type == "admin":
            return redirect(url_for("admin.home"))
        else:
            flash("Account type not recognised. Please contact support.", "error")
            raise ValueError(f"Incorrect account type {user.type}")
    except ValueError as e:
        logger.warning(f"Finalising login failed: {e}")
        return redirect(url_for("login_auth_bp.login"))
