import logging

from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.utilities.utils import clean_input, generate_otp, send_otp_email, clear_session_data, set_otp_session_data, validate_otp, check_otp_hash


# Initialise flask blueprint - 'signup_aut_bp'
signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__, url_prefix="/signup")

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER: str = "authentication/signup"


# Initial signup route
@signup_auth_bp.route("/", methods=["POST", "GET"])
def signup():
    """Handle initial signup by asking for username & email, then send OTP to email provided."""

    # Create form to render
    form = InitialSignupForm()

    # Clear existing signup related session data
    clear_session_data(["username", "email", "otp_data", "login_stage"])

    # Redirect to login if pressed 'login'
    if request.args.get("action") == "login":
        return redirect(url_for("login_auth_bp.login"))

    # Handle POST request with validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise inputs
        username = clean_input(form.username.data)
        email = clean_input(form.email.data)

        # Store data in session for future stages & sending of OTP
        session_data = {"username": username, "email": email, "signup_stage": "otp"}
        session.update(session_data)

        return redirect(url_for("signup_auth_bp.send_otp"))

    return render_template(f"{TEMPLATE_FOLDER}/signup.html", form=form)


# Resend OTP route
@signup_auth_bp.route("/send_otp", methods=["GET"])
def send_otp():
    """Send/ Resend the OTP to the user's email."""

    # Retrieve username & email from session
    username = session.get("username")
    email = session.get("email")

    # Generate OTP & current time
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
        flash("Failed to  OTP. Please try again.", "error")
        logger.error(f"Failed to resend OTP to {email} for user {username}")

    return redirect(url_for("signup_auth_bp.verify_email"))


# Email verification route
@signup_auth_bp.route("/verify_email", methods=["POST", "GET"])
def verify_email():
    """Verify the OTP sent to user's email."""

    # Create form to render
    form = VerifyOtpForm()

    # Redirect to signup if pressed 'back'
    if request.args.get("action") == "back":
        clear_session_data(["username", "email", "otp_data", "signup_stage"])
        return redirect(url_for("signup_auth_bp.signup")) 

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
            session.update({"otp_data": otp_data, "login_stage": "password"})
        except Exception as e:
            flash("Invalid OTP. Please try again.", "error")
            logger.error(f"Invalid email verification: {e}")
        else:
            return redirect(url_for("signup_auth_bp.set_password"))
    
    return render_template(f"{TEMPLATE_FOLDER}/verify_email.html", form=form)


# Set password route (for manual signups)
@signup_auth_bp.route("/set_password", methods=["POST", "GET"])
def set_password():
    """Allow member user to set a password after OTP verification"""

    # Create form to render
    form = SetPasswordForm()

    # Redirect to singup if pressed 'back'
    if request.args.get("action") == "back":
        clear_session_data(["username", "email", "otp_data", "signup_stage"])
        return redirect(url_for("signup_auth_bp.signup"))

    # Handle POST request and validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve username & email from session
        username, email = session.get("username"), session.get("email")

        # Hash inputted password
        password_hash = generate_password_hash(form.password.data)

        # Create member with retrieved credentials
        try:
            member = Member.create(username=username, email=email, password_hash=password_hash)

            # Unsuccessful account creation
            if not member:
                raise Exception("Failed to create member account.")

            # Successful account creation
            session["signup_stage"] = "extra_info"
            flash("Account created successfully. Please continue.", "success")
            logger.info(f"Member account created for user {username} with email {email}.")
            return redirect(url_for("signup_auth_bp.extra_info"))

        # Handle failed account creation
        except Exception as e:
            flash("Account creation failed. Please try again.", "error")
            logger.error(f"Failed to create member account for username: {username}, email: {email}")
            return redirect(url_for("signup_auth_bp.set_password"))

    return render_template(f"{TEMPLATE_FOLDER}/set_password.html", form=form)


# Extra info route (to get Phone number, Address, Postal code)
@signup_auth_bp.route("/extra_info", methods=["POST", "GET"])
def extra_info():
    """Capture extra user information after account creation."""

    # Create form to render
    form = PhoneAddressForm()

    # Retrieve username & email from session
    username, email = session.get("username"), session.get("email")

    # Check whether account exists
    member = Member.query.filter_by(username=username, email=email).first()

    if not member:
        flash("Account doesn't exist. Please restart the signup process.", "error")
        logger.error(f"Member not found for username: {username}, email: {email} when trying to submit extra info.")
        return redirect(url_for("signup_auth_bp.signup"))
    
    # Handle POST request
    if request.method == "POST":
        # Retrieve action to respond accordingly
        action = request.form.get("action")

        # Handle "skip" action
        if action == "skip":
            flash("You can log in now.", "success")
            logger.info(f"No extra info saved for member {username}.")

        # Handle "complete" action
        elif action == "complete" and form.validate_on_submit():
            # Save info to database
            try:
                # Retrieve & sanitise inputs
                phone_number = clean_input(form.phone_number.data)
                address = clean_input(form.address.data)
                postal_code = clean_input(form.postal_code.data)

                # Update only if input provided
                if phone_number: member.phone_number = phone_number
                if address: member.address = address
                if postal_code: member.postal_code = postal_code

                db.session.commit()

                flash("Extra inforamtion saved. You can log in now.", "success")
                logger.info(f"Extra info saved for member '{username}'.")

            # Handle any exceptions when saving data
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred when trying to save your data. Please try again", "error")
                logger.error(f"Failed to save extra info for user '{username}': {e}")
                print("error")

                return redirect(url_for("signup_auth_bp.extra_info"))

        # Clear session data
        clear_session_data(["username", "email", "otp_data", "signup_stage"])

        return redirect(url_for("login_auth_bp.login"))
    return render_template(f"{TEMPLATE_FOLDER}/extra_info.html", form=form)
