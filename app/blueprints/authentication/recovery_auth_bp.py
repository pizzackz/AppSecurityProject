import logging

from logging import Logger
from flask import Blueprint, request, redirect, render_template, url_for, flash, session

from app.models import User
from app.forms.auth_forms import VerifyOtpForm, AccountRecoveryForm, RecoverOptionsForm
from app.utilities.utils import clean_input, generate_otp, set_otp_session_data, clear_session_data, send_otp_email, validate_otp, check_otp_hash
from app.utilities.authentication.recovery_utils import get_user_by_email, validate_recovery_option, handle_recovery_option


# Initialise flask blueprint - 'login_aut_bp'
recovery_auth_bp: Blueprint = Blueprint("recovery_auth_bp", __name__, url_prefix="/recovery")

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "authentication/recovery"


# Initial account recovery route (Retrieve email)
@recovery_auth_bp.route("/", methods=["GET", "POST"])
def recovery():
    """Process user inputted email to initiate account recovery process"""

    # Create form to render
    form: AccountRecoveryForm = AccountRecoveryForm()
    
    # Clear existing recovery related session data
    clear_session_data(["email", "otp_data", "recovery_stage"])

    # Redirect to recovery if pressed 'back'
    if request.args.get("action") == "back":
        return redirect(url_for("login_auth_bp.login"))

    # Handle POST request & validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise input
        email = clean_input(form.email.data)

        try:
            # Retrieve user to check
            user = get_user_by_email(email)

            # Store session data
            session.update({"email": email, "recovery_stage": "otp"})
        except ValueError as e:
            flash("Please enter an email for an existing account.", "error")
            logger.warning(f"Account recovery attempt with non-existent email: {email}")
            return redirect(url_for("recovery_auth_bp.recovery"))
        else:
            return redirect(url_for("recovery_auth_bp.send_otp"))
    
    return render_template(f"{TEMPLATE_FOLDER}/recovery.html", form=form)


# Send OTP route
@recovery_auth_bp.route("/send_otp", methods=["GET"])
def send_otp():
    """Send/ Resend the OTP to the user's email."""

    # Retrieve username & email from session
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
        logger.info(f"OTP sent to '{email}'.")
    else:
        if request.args.get("resend"):
            flash("Failed to resend OTP. Please try again.", "error")
        else:
            flash("Failed to send OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to '{email}'.")

    return redirect(url_for("recovery_auth_bp.verify_email"))


# Email verification route
@recovery_auth_bp.route("/verify_email", methods=["POST", "GET"])
def verify_email():
    """Verify the OTP sent to user's email."""

    # Create form to render
    form = VerifyOtpForm()

    # Redirect to recovery if pressed 'back'
    if request.args.get("action") == "back":
        clear_session_data(["email", "otp_data", "recovery_stage"])
        return redirect(url_for("recovery_auth_bp.recovery"))

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
            session.update({"otp_data": otp_data, "recovery_stage": "options"})
        except Exception as e:
            flash("Invalid OTP. Please try again.", "error")
            logger.error(f"Invalid email verification attempt: {e}")
        else:
            return redirect(url_for("recovery_auth_bp.recovery_options"))

    return render_template(f"{TEMPLATE_FOLDER}/verify_email.html", form=form)


# Recovery options route
@recovery_auth_bp.route("/options", methods=["POST", "GET"])
def recovery_options():
    """Handles the options for account recovery (recovery username or change password)."""

    # Create form to render
    form: RecoverOptionsForm = RecoverOptionsForm()

    # Redirect to recovery if pressed 'back'

    if request.args.get("action") == "back":
        clear_session_data(["email", "otp_data", "recovery_stage"])
        return redirect(url_for("recovery_auth_bp.recovery"))
    
    # Handle POST request & validated form
    if request.method == "POST" and form.validate_on_submit():
        try:
            # Retrieve option from form
            option = clean_input(form.recovery_option.data)

            # Retrieve email from session
            email = session.get("email")
            print(option)

            handle_recovery_option(option, email)
        except ValueError as e:
            flash("Invalid option chosen. Please try again.", "error")
            logger.warning(f"Selecting recovery options failed: {e}")
        else:
            # Redirect based on the selected option
            if option == "recover_username":
                session["recovery_stage"] = "username"
                return redirect(url_for("login_auth_bp.recover_username"))
            elif option == "change_password":
                session["recovery_stage"] = "password"
                return redirect(url_for("login_auth_bp.change_password"))
    
    return render_template(f"{TEMPLATE_FOLDER}/recovery_options.html", form=form)
