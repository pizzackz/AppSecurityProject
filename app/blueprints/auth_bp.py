import logging

from logging import Logger
from datetime import datetime
from flask import Blueprint, render_template, session, url_for, flash, redirect, request, current_app
from flask_login import login_user
from werkzeug.security import generate_password_hash
from typing import Optional, Dict, List

from app import db
from app.models import User, Member
from app.forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.utils import clean_input, generate_otp, send_otp_email, clear_signup_session, handle_user_not_found, session_required, set_session_data, validate_otp_data

auth_bp: Blueprint = Blueprint("auth_bp", __name__)

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Initial signup route
@auth_bp.route("/signup", methods=["POST", "GET"])
def initial_signup():
    """Handle initial signup by asking for username and email, and send OTP to email provided."""
    # If username or email already in session, clear it & inform user
    if session.get("username") or session.get("email"):
        clear_signup_session()
        flash("It seems you were already in the process of signing up. Please start again.", "warning")
        logger.warning("User attempted to restart signup with existing session data (username, email), session data cleared.")

    # Create form to render
    form = InitialSignupForm()

    # Handle validated form, input data sanitised before validation
    if request.method == "POST" and form.validate_on_submit():
        # Sanitise inputs
        username: str = clean_input(form.username.data)
        email: str = clean_input(form.email.data)
        
        # Check whether account already exists
        if User.query.filter_by(username=username, email=email).first():
            # 'user' found, redirect to login
            flash("User already exists. Please login.", "info")
            logger.info(f"User {username} with email {email} tried to signup but account already exists.")

            # TODO: Redirect to login
            # return redirect(url_for("auth_bp.login"))
            return "User exists, please login now"

        # Generate OTP & current time
        otp: str = generate_otp()
        current_time: datetime = datetime.now()
        otp_data: Dict = {"value": otp, "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")}

        # Store session data (username, email, otp_data)
        set_session_data({"username": username, "email": email, "otp_data": otp_data})

        # Send OTP email
        if send_otp_email(email, otp):
            # Redirect to next step (verify_otp) when successful
            flash("An OTP has been sent to your email.", "info")
            logger.info(f"OTP sent to {email} for user {username}.")
            return redirect(url_for("auth_bp.verify_otp"))

        # Handle unsuccessful sending of OTP
        clear_signup_session()  # Clear session data
        flash("Failed to send OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {email} for user {username}")

    return render_template("authentication/initial_signup.html", form=form)


# OTP verification route
@auth_bp.route("/verify_otp", methods=["POST", "GET"])
@session_required(
    keys=["username", "email", "otp_data"],
    flash_message="Your session has expired or you have not completed the signup process.",
    log_message="Session keys missing for OTP verification: {missing_keys}"
)
def verify_otp():
    """Verify the OTP sent to user's email."""
    # Create form to render
    form: VerifyOtpForm = VerifyOtpForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve OTP data from form and session
        input_otp: str = clean_input(form.otp.data)
        otp_data: Dict = session.get("otp_data")

        # Validate otp_data
        required_keys: List[str] = ["value", "generation_time"]
        if not validate_otp_data(otp_data, required_keys, expiry_time=5, otp_length=6):
            # Inform user otp invalid/ expired, redirect to same route
            flash("OTP is invalid or has expired. Please request a new OTP.", "error")
            logger.warning(f"Invalid or expired OTP attempt for user {session['username']} with email {session['email']}")
            return redirect(url_for("auth_bp.verify_otp"))

        # Compare OTPs
        if input_otp != otp_data.get("value"):
            # Handle incorrect otp, redirect to verify_otp to force refresh
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user {session["username"]} with email {session["email"]}.")
            return redirect(url_for("auth_bp.verify_otp"))

        # OTP matches, proceed to set password
        session.pop("otp_data", None)  # Remove otp_data from session
        flash("OTP verified successfully. Please set your password", "success")
        logger.info(f"OTP verified for user {session["username"]} with email {session["email"]}.")
        return redirect(url_for("auth_bp.set_password"))

    return render_template("authentication/verify_otp.html", form=form)


# Resend OTP route
@auth_bp.route("/resend_otp", methods=["GET"])
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
    otp_data: Dict = {"value": otp, "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S")}
    set_session_data({"otp_data": otp_data})  # Store otp_data in session

    # Send OTP email
    if send_otp_email(email, otp):
        # Successful resend
        flash("A new OTP has been sent to your email.", "info")
        logger.info(f"OTP sent to {email} for user {username}.")
    else:
        # Unsuccessful resend
        flash("Failed to resend OTP. Please try again.", "error")
        logger.error(f"Failed to resend OTP to {email} for user {username}")

    return redirect(url_for("auth_bp.verify_otp"))


# Set password route (For initial signups)
@auth_bp.route("/set_password", methods=["POST", "GET"])
@session_required(["username", "email"])
def set_password():
    """Allow member user to set a password after OTP verification."""
    # Create form to render
    form: SetPasswordForm = SetPasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise provided password
        # Retrieve stored username and email
        # Hash inputted password
        password: str = clean_input(form.password.data, False)
        username: Optional[str] = session.get("username")
        email: Optional[str] = session.get("email")
        hashed_password: Optional[str] = generate_password_hash(password)

        # Session data retrieval unsuccessful
        if not username or not email:
            flash("An error occurred. Please try again.", "error")
            logging.error("Missing username or email in session during set_password.")
            return redirect(url_for("auth_bp.set_password"))

        # Session data retrieval successful
        try:
            # Create new member
            member: Optional[Member] = Member.create(username=username, email=email, password_hash=hashed_password)

            # Member account creation unsuccessful
            if not member:
                raise Exception("Failed to create member account.")

            # Member account creation successful
            flash("Account created successfully. Please continue.", "success")
            logger.info(f"Member account created for user {username} with email {email}.")
            return redirect(url_for("auth_bp.additional_info"))

        # Handle failed account creation
        except Exception as e:
            flash("Account creation failed. Please try again.", "error")
            logger.error(f"Failed to create member account for username: {username}, email: {email}")
            return redirect(url_for("auth_bp.set_password"))

    return render_template("authentication/set_password.html", form=form)


# Additional info route (Phone number, address, postal code)
@auth_bp.route("/additional_info", methods=["POST", "GET"])
@session_required(["username", "email"])
def additional_info():
    """Capture additional user information after account creation."""
    form: PhoneAddressForm = PhoneAddressForm()
    print("correct 2")

    if request.method == "POST":
        # Get action type to respond accordingly
        action: Optional[str] = request.form.get("action")

        # Handle invalid actions
        if action not in ("skip", "complete"):
            flash("Invalid action. Please try again.", "error")
            logger.warning(f"Invalid action '{action}' attempted in additional_info.")
            return redirect(url_for("auth_bp.additional_info"))

        # Get member info from session
        # Get member object from database based on member info
        username: Optional[str] = session.get("username")
        email: Optional[str] = session.get("email")
        member: Optional[Member] = Member.query.filter_by(username=username, email=email).first()

        # Remove temporary session data
        clear_signup_session()

        # Handle 'member' object not found
        if not member:
            handle_user_not_found(username, email, "member")
            return redirect(url_for("auth_bp.initial_signup"))

        # Handle 'skip' action
        if action == "skip":
            # 'member' exists, log member in
            flash("Logged in successfully.", "success")
            logger.info(f"Member {username} logged in without providing additional info.")
            login_user(member)

        # Handle 'complete' action
        if action == "complete" and form.validate_on_submit():
            try:
                # 'member' exists, inputted data validated, save additional info
                member.phone_number = clean_input(form.phone_number.data)
                member.address = clean_input(form.address.data)
                member.postal_code = clean_input(form.postal_code.data)
                db.session.commit()

                # Log member in, display success message
                flash("Addtional information saved and logged in successfully.", "success")
                logger.info(f"Additional info saved for member {username}.")
                login_user(member)

            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred when trying to save your data. Please try again", "error")
                logger.error(f"Failed to save additional info for user {username}, email {email}. Error: {e}")

                # Reset temporary session data, Redirect back to this route
                session["username"], session["email"] = member.username, member.email

                return redirect(url_for("auth_bp.additional_info"))

        # Redirect to homapge upon successful handling of 'skip' and 'complete' actions
        # TODO: Redirect to standard member homepage
        # return redirect(url_for("member_bp.home"))
        return "Extra info saved, redirect to homepage"

    print("correct 3")

    if isinstance(form, PhoneAddressForm):
        print("correct 4")
    else:
        print("wrong")
    return render_template("authentication/additional_info.html", form=form)
