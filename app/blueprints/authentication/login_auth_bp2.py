import logging

from logging import Logger
from datetime import datetime
from flask import Blueprint, request, redirect, render_template, url_for, flash, session, current_app
from flask_login import login_user, LoginManager
from werkzeug.security import check_password_hash
from typing import Optional, Dict, List

from app import db, login_manager
from app.models import User, Authentication
from app.forms.auth_forms import InitialLoginForm, VerifyOtpForm, AccountRecoveryForm, RecoverOptionsForm
from app.utils import session_required, clean_input, generate_otp, send_otp_email, set_session_data, validate_otp_data, clear_session_data


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

    # Clear session data to start fresh
    clear_session_data(["username", "email", "otp_data", "login_stage", "recover_acc_stage", "source"])

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

            # Handle no user account
            if not user:
                flash("Invalid username or password", "error")
                logger.error(f"Login attempt failed: Username '{username}' not found.")
                return render_template("authentication/login/initial_login.html", form=form)
            
            # Handle user type not allowed
            if user.type not in ("member", "admin"):
                flash("An error occurred. Please try signing in again later.", "error")
                logger.error(f"User type '{user.type}' for user '{username}' not allowed.")
                return render_template("authentication/login/initial_login.html", form=form)

            # Retrieve authentication record using user.id
            authentication: Authentication = Authentication.query.filter_by(id=user.id).first()

            # Handle no authentication record or incorrect password
            if not (authentication and check_password_hash(authentication.password_hash, password)):
                flash("Invalid username or password", "error")
                logger.error(f"Login attempt failed: Incorrect password for username '{username}'.")
                return render_template("authentication/login/initial_login.html", form=form)

            # Generate & send OTP
            email: str = user.email
            otp: str = generate_otp()
            current_time: datetime = datetime.now()
            otp_data: Dict = {
                "value": otp,
                "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")
            }
            # Store session data (username, email, otp_data)
            set_session_data({
                "username": username,
                "email": email,
                "otp_data": otp_data,
                "login_stage": "otp",
                "source": "initial_login"
            })

            # Send OTP email
            if send_otp_email(email, otp):
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
    keys=["username", "email", "otp_data", "source"],
    redirect_link="login_auth_bp.initial_login",
    flash_message="Your session has expired or you have not started logging in or recovering your account.",
    log_message="Session keys missing for OTP verification: {missing_keys}"
)
def verify_otp():
    """Handles OTP verification."""
    # If source in session != "login_stage" or "recover_acc_stage", redirect to initial_login
    if session.get("source") not in ("initial_login", "account_recovery"):
        flash("Please start to login or recover account first.", "warning")
        logger.warning(f"Attempted to verify OTP without starting login or recovering account.")
        return redirect(url_for("login_auth_bp.initial_login"))

    # If pressed 'Back', clear login related data (username, email, otp_data, login_stage, recover_acc_stage), redirect to initial_login or account_recovery
    if request.args.get("action") == "back":
        endpoint: str = "login_auth_bp.initial_login"

        if session.get("source") == "account_recovery":
            endpoint = "login_auth_bp.account_recovery"

        clear_session_data(["username", "email", "otp_data", "source", "login_stage", "recover_acc_stage"])
        return redirect(url_for(endpoint))

    # TODO: Redirect to correct stages if "login_stage" != "otp", if "recover_acc_stage" != "otp"
    if "otp" not in (session.get("login_stage", None), session.get("recover_acc_stage", None)):
        if session.get("login_stage", None) != "otp":
            return redirect(url_for("login_auth_bp.initial_login"))

    # Create form to render
    form: VerifyOtpForm = VerifyOtpForm()

    if request.method == "POST":
        action: str = request.form.get("action")
        source: str = session.get("source")

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
            
            # Handle OTP match
            if source == "account_recovery":
                flash("Email verified successfully. Please choose your recovery option", "success")
                logger.info(f"OTP verified for account recovery for user with email {session['email']}.")
                return redirect(url_for("login_auth_bp.recovery_options"))

            # Retrieve user from database
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

            # Handle user not found or user type invalid
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


# Account recovery stage 1 route - get email to retrieve account details for
@login_auth_bp.route("/login/account_recovery", methods=["POST", "GET"])
def account_recovery():
    """Process user inputted email to initiate account recovery process"""
    # If pressed 'Back', redirect to initial_signup
    if request.args.get("action") == "back":
        return redirect(url_for("login_auth_bp.initial_login"))

    # Create form to render
    form: AccountRecoveryForm = AccountRecoveryForm()

    if request.method == "POST":
        action: str = request.form.get("action")

        if action == "next" and form.validate_on_submit():
            # Sanitise email input
            # Check if user exists with provided email
            email: str = clean_input(form.email.data)
            user: User = User.query.filter_by(email=email).first()

            # Handle no 'user' object found (account doesn't exist)
            if not user:
                flash("Please enter an email for an existing account.", "error")
                logger.warning(f"Account recovery attempt with non-existent email: {email}")
                return render_template("authentication/login/account_recovery.html", form=form)
            
            # Generate OTP & current time
            otp: str = generate_otp()
            current_time: datetime = datetime.now()
            otp_data: Dict = {
                "value": otp,
                "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")
            }
            # Store session data (username, email, otp_data, recover_acc_stage)
            set_session_data({
                "username": user.username,
                "email": email,
                "otp_data": otp_data,
                "recover_acc_stage": "otp",
                "source": "account_recovery"
            })

            # Send email
            if send_otp_email(email, otp):
                flash("An OTP has been sent to your email.", "info")
                logger.info(f"OTP sent to {email} for account recovery.")
                print(session)
                return redirect(url_for("login_auth_bp.verify_otp"))
            
            # Handle unsuccessful sending of OTP
            flash("Failed to send OTP. Please try again.", "error")
            logger.error(f"Failed to send OTP to {email} for account recovery.")

    return render_template("authentication/login/account_recovery.html", form=form)


# Recovery options route
@login_auth_bp.route("/login/recovery_options", methods=["POST", "GET"])
@session_required(
    keys=["email", "otp_data", "recover_acc_stage"],
    redirect_link="login_auth_bp.account_recovery",
    flash_message="Your session has expired or you have not started the recovery process",
    log_message="Session keys missing for recovery options: {missing_keys}"
)
def recovery_options():
    """Handles the options for account recovery (recovery username or change password)."""

    # If pressed 'Back', clear session data related to recovery, redirect to account_recovery
    if request.args.get("action") == "back":
        clear_session_data(["username", "email", "otp_data", "recover_acc_stage", "source"])
        return redirect(url_for("login_auth_bp.account_recovery"))
    
    # Create form to render
    form: RecoverOptionsForm = RecoverOptionsForm()

    if request.method == "POST":
        action: str = request.form.get("action")
        option: str = form.recovery_option.data
        
        # Handle invalid option
        if option not in ("recover_username", "change_password"):
            flash("Invalid option. Please choose a valid recovery option.", "error")
            logger.warning(f"Invalid option '{option}' chosen by user  with email '{session['email']}'")
            return redirect(url_for("login_auth_bp.recovery_options"))
        
        # Handle invalid action
        if action != "next":
            return redirect(url_for("login_auth_bp.recovery_options"))

        # Handle recover username
        if option == "recover_username":
            logger.info(f"User with email '{session['email']}' chose to recover username.")
            # TODO: Redirect to recover_username
            # return redirect(url_for("login_auth_bp.recover_username"))
            return "Redirecting to recover username..."
        
        # Handle change password
        if option == "change_password":
            logger.info(f"User with email '{session['email']}' chose to change password.")
            # TODO: Redirect to change_password
            # return redirect(url_for("login_auth_bp.change_password"))
            return "Redirecting to change password..."

    return render_template("authentication/login/recovery_options.html", form=form)
