import logging

from logging import Logger
from datetime import datetime
from flask import Blueprint, request, redirect, render_template, url_for, flash, session, current_app
from flask_login import login_user, LoginManager
from werkzeug.security import check_password_hash
from typing import Optional, Dict, List

from app import db, login_manager
from app.models import User, Authentication
from app.forms.auth_forms import InitialLoginForm, VerifyOtpForm, RecoverOptionsForm
from app.utils import session_required, clean_input, generate_otp, send_otp_email, set_session_data, validate_otp_data


# Initialise flask blueprint - 'login_aut_bp'
login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__)

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# User loader function to retrieve user object from database
@login_manager.user_loader
def load_user(user_id: int) -> User:
    return User.query.get(int(user_id))


# Initial login route
@login_auth_bp.route("/login", methods=["POST", "GET"])
def initial_login():
    """Handles the initial login process."""
    # Create form to render
    form: InitialLoginForm = InitialLoginForm()

    # If pressed 'Create Account, redirect to initial_signup
    if request.args.get("action") == "create_account":
        return redirect(url_for("signup_auth_bp.initial_signup"))

    # Handle POST request
    if request.method == "POST":
        action: str = request.form.get("action")

        if action == "login" and form.validate_on_submit():
            # Sanitise inputs
            username: str = clean_input(form.username.data)
            password: str = clean_input(form.password.data, False)

            # Retrieve user from database
            user: User = User.query.filter_by(username=username).first()

            # Handle no user account or user type not allowed
            if not user:
                logger.error(f"Login attempt failed: Username '{username}' not found.")
                flash("Invalid username or password", "error")
                return render_template("authentication/login/initial_login.html", form=form)
            elif user.type not in ("member", "admin"):
                logger.error(f"User type '{user.type}' for user '{username}' not allowed.")
                flash("An error occurred. Please try signing in again later.", "error")
                return render_template("authentication/login/initial_login.html", form=form)
            
            # Retrieve authentication record using user.id
            authentication: Authentication = Authentication.query.filter_by(id=user.id).first()

            # Handle no authentication record or incorrect password
            if not (authentication and authentication.password_hash == password):
                logger.error(f"Login attempt failed: Incorrect password for username '{username}'.")
                flash("Invalid username or password", "error")
                return render_template("authentication/login/initial_login.html", form=form)
            # if not (authentication and check_password_hash(authentication.password_hash, password)):
            #     logger.error(f"Login attempt failed: Incorrect password for username '{username}'.")
            #     flash("Invalid username or password", "error")
            #     return render_template("authentication/login/initial_login.html", form=form)

            # Generate & send OTP
            email: str = user.email
            otp: str = generate_otp()
            current_time: datetime = datetime.now()
            otp_data: Dict = {
                "value": otp,
                "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")
            }
            set_session_data({"username": username, "email": email, "otp_data": otp_data, "login_stage": "otp"})  # Store session data (username, email, otp_data)

            # Send OTP email
            if send_otp_email(email, otp):
                # Redirect to next step (verify_otp) when successful
                flash("An OTP has been sent to your email.", "info")
                logger.info(f"OTP sent to {email} for user {username}.")
                return redirect(url_for("login_auth_bp.verify_otp"))

            # Handle unsuccessful sending of OTP
            flash("Failed to send OTP. Please try again.", "error")
            logger.error(f"Failed to send OTP to {email} for user {username}")

        # Handle invalid action type
        if action != "login":
            logger.warning(f"Attempted form submission with action '{action}'.")

    return render_template("authentication/login/initial_login.html", form=form)


# OTP verification route
@login_auth_bp.route("/login/verify_otp", methods=["POST", "GET"])
@session_required(
    keys=["username", "email", "otp_data"],
    redirect_link="login_auth_bp.initial_login",
    flash_message="Your session has expired or you have not started the login process",
    log_message="Session keys missing for OTP verification: {missing_keys}"
)
def verify_otp():
    """Handles OTP verification."""
    # TODO: If login_stage in session != "otp", redirect to correct stage

    # If pressed 'Back', clear "signup_stage", redirect to initial_signup
    if request.args.get("action") == "back":
        session.pop("signup_stage")
        return redirect(url_for("login_auth_bp.initial_login"))

    # Create form to render
    form: VerifyOtpForm = VerifyOtpForm()

    if request.method == "POST":
        action: str = request.form.get("action")

        if action == "next" and form.validate_on_submit():
            # Retrieve OTP data from form and session
            input_otp: str = clean_input(form.otp.data)
            otp_data: Dict = session.get("otp_data")

            # Validate otp_data
            required_keys: List[str] = ["value", "generation_time"]
            if not validate_otp_data(otp_data, required_keys, expiry_time=5, otp_length=6):
                # Inform user otp invalid/ expired, redirect to same route
                flash("OTP is invalid or has expired. Please request a new OTP.", "error")
                logger.warning(f"Invalid or expired OTP attempt for user {session['username']} with email {session['email']}")
                return redirect(url_for("login_auth_bp.verify_otp"))

            # Compare OTPs
            if input_otp != otp_data.get("value"):
                # Handle incorrect otp, redirect to verify_otp to force refresh
                flash("Invalid OTP. Please try again.", "error")
                logger.warning(f"Invalid OTP attempt for user {session['username']} with email {session['email']}.")
                return redirect(url_for("login_auth_bp.verify_otp"))

            # OTP matches, Retrieve user from database
            user: Optional[User] = User.query.filter_by(username=session.get("username")).first()

            # Handle no user found
            if user:
                login_user(user)
                flash("Login successful!", "success")
                logger.info(f"User '{session['username']}' logged in successfully.")

                # TODO: Redirect to appropriate homepages
                if user.type == "member":
                    # return redirect(url_for("member.member_homepage"))
                    return "Redirecting to member homepage..."
                elif user.type == "admin":
                    # return redirect(url_for("admin.admin_homepage"))
                    return "Redirecting to admin homepage..."

                flash("Email verified successfully. Please set your password", "success")
                logger.info(f"OTP verified for user {session['username']} with email {session['email']}.")
                return redirect(url_for("signup_auth_bp.set_password"))

            # Handle user not found
            flash("User account not found. Please try again.", "error")
            logger.error(f"User '{session['username']}' not found after OTP verification.")

    return render_template("authentication/login/verify_otp.html", form=form)


# Resend OTP route
@login_auth_bp.route("/login/resend_otp", methods=["GET"])
@session_required(
    keys=["username", "email"],
    flash_message="Your session has expired. Please start the signup process again.",
    log_message="Attempt to resend OTP without valid session data: {missing_keys}"
)
def resend_otp():
    """Resend the OTP to the user's email."""
    # Retrieve username & email
    username: str = session.get("username")
    email = session.get("email")

    # Clear any existing OTP data in session
    session.pop("otp_data", None)

    # Generate OTP & current time
    otp: str = generate_otp()
    current_time: datetime = datetime.now()
    otp_data: Dict = {
        "value": otp,
        "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")
    }
    session["otp_data"] = otp_data # Store otp_data in session

    # Send OTP email
    if send_otp_email(email, otp):
        # Successful resend
        flash("A new OTP has been sent to your email.", "info")
        logger.info(f"OTP sent to {email} for user {username}.")
    else:
        # Unsuccessful resend
        flash("Failed to resend OTP. Please try again.", "error")
        logger.error(f"Failed to resend OTP to {email} for user {username}")

    return redirect(url_for("login_auth_bp.verify_otp"))


# Account recovery options route
@login_auth_bp.route("/login/account_recovery", methods=["POST", "GET"])
def account_recovery():
    """Handle account recovery process based on selected option"""
    # Create form to render
    form: RecoverOptionsForm = RecoverOptionsForm()

    if request.method == "POST":
        # TODO: Account recovery processes
        #TODO: Proper redirects
        return "Redirecting you to recover your account details..."
    
    # TODO: GET request processes (if any)
    # TODO: Render account recovery page
    # return render_template("authentication/login/account_recovery.html", form=form)
    return "Rendering account recovery page..."
