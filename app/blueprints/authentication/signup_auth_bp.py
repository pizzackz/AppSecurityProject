import logging

from logging import Logger
from datetime import datetime
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_login import login_user
from werkzeug.security import generate_password_hash
from typing import Optional, Dict, List

from app import db
from app.models import User, Member
from app.forms.auth_forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.utils import clean_input, generate_otp, send_otp_email, session_required, clear_session_data, set_session_data, validate_otp_data, signup_stage_redirect

signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__)

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Initial signup route
@signup_auth_bp.route("/signup", methods=["POST", "GET"])
def initial_signup():
    """Handle initial signup by asking for username and email, and send OTP to email provided."""
    # If signup_stage in session, redirect to correct stage
    if session.get("signup_stage"):
        return signup_stage_redirect("initial_signup")

    # Create form to render
    form = InitialSignupForm()

    # Clear session data to start fresh
    clear_session_data(["username", "email", "otp_data"])

    # If pressed 'login', redirect to initial_login
    if request.args.get("action") == "login":
        return redirect(url_for("login_auth_bp.initial_login"))

    # Handle validated form, input data sanitised before validation
    if request.method == "POST":
        action: str = request.form.get("action")

        # Handle if pressed 'Next'
        if action == "next" and form.validate_on_submit():
            # Sanitise inputs
            username: str = clean_input(form.username.data)
            email: str = clean_input(form.email.data)
            
            # Check whether account already exists
            if User.query.filter_by(username=username, email=email).first():
                # 'user' found, redirect to login
                flash("User already exists. Please login.", "info")
                logger.info(f"User {username} with email {email} tried to signup but account already exists.")

                return redirect(url_for("login_auth_bp.initial_login"))

            # Generate OTP & current time
            otp: str = generate_otp()
            current_time: datetime = datetime.now()
            otp_data: Dict = {
                "value": otp,
                "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S"),
                "verified": False
            }

            # Store session data (username, email, otp_data)
            set_session_data({"username": username, "email": email, "otp_data": otp_data, "signup_stage": "otp"})

            # Send OTP email
            if send_otp_email(email, otp):
                # Redirect to next step (verify_otp) when successful
                flash("An OTP has been sent to your email.", "info")
                logger.info(f"OTP sent to {email} for user {username}.")
                return redirect(url_for("signup_auth_bp.verify_otp"))

            # Handle unsuccessful sending of OTP
            flash("Failed to send OTP. Please try again.", "error")
            logger.error(f"Failed to send OTP to {email} for user {username}")

    # Handle GET request, POST request w/o proper action, POST request failed to send email
    return render_template("authentication/signup/initial_signup.html", form=form)


# OTP verification route
@signup_auth_bp.route("/signup/verify_otp", methods=["POST", "GET"])
@session_required(
    keys=["username", "email", "otp_data"],
    flash_message="Your session has expired or you have not started the signup process.",
    log_message="Session keys missing for OTP verification: {missing_keys}"
)
def verify_otp():
    """Verify the OTP sent to user's email."""
    # If signup_stage in session != "otp", redirect to correct stage
    if session.get("signup_stage") != "otp":
        return signup_stage_redirect("otp")
    
    # If pressed 'Back', clear "signup_stage", redirect to initial_signup
    if request.args.get("action") == "back":
        session.pop("signup_stage")
        return redirect(url_for("signup_auth_bp.initial_signup"))

    # Create form to render
    form: VerifyOtpForm = VerifyOtpForm()

    if request.method == "POST":
        action: str = request.form.get("action")

        if action == "next" and form.validate_on_submit():
            # Retrieve OTP data from form and session
            input_otp: str = clean_input(form.otp.data)
            otp_data: Dict = session.get("otp_data")

            # Validate otp_data
            required_keys: List[str] = ["value", "generation_time", "verified"]
            if not validate_otp_data(otp_data, required_keys, expiry_time=5, otp_length=6):
                # Inform user otp invalid/ expired, redirect to same route
                flash("OTP is invalid or has expired. Please request a new OTP.", "error")
                logger.warning(f"Invalid or expired OTP attempt for user {session['username']} with email {session['email']}")
                return redirect(url_for("signup_auth_bp.verify_otp"))

            # Compare OTPs
            if input_otp != otp_data.get("value"):
                # Handle incorrect otp, redirect to verify_otp to force refresh
                flash("Invalid OTP. Please try again.", "error")
                logger.warning(f"Invalid OTP attempt for user {session['username']} with email {session['email']}.")
                return redirect(url_for("signup_auth_bp.verify_otp"))

            # OTP matches, update verification status & time, proceed to set password
            otp_data["verified"] = True
            set_session_data({"otp_data": otp_data, "signup_stage": "password"})
        
            flash("Email verified successfully. Please set your password", "success")
            logger.info(f"OTP verified for user {session['username']} with email {session['email']}.")
            return redirect(url_for("signup_auth_bp.set_password"))

    # Handle GET request, POST request w/o proper action
    return render_template("authentication/signup/verify_otp.html", form=form)


# Resend OTP route
@signup_auth_bp.route("/signup/resend_otp", methods=["GET"])
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
        "generation_time": current_time.strftime("%d/%b/%Y %H:%M:%S"),
        "verified": False
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

    return redirect(url_for("signup_auth_bp.verify_otp"))


# Set password route (For initial signups)
@signup_auth_bp.route("/signup/set_password", methods=["POST", "GET"])
@session_required(["username", "email", "otp_data"],
    log_message="Session keys missing for setting password: {missing_keys}"
)
def set_password():
    """Allow member user to set a password after OTP verification."""
    # If signup_stage in session != "password", redirect to correct stage
    if session.get("signup_stage") != "password":
        return signup_stage_redirect("password")
    
    # If pressed 'Back', clear "signup_stage", redirect to initial_signup
    if request.args.get("action") == "back":
        session.pop("signup_stage")
        return redirect(url_for("signup_auth_bp.initial_signup"))

    # Create form to render, Retrive otp data
    form: SetPasswordForm = SetPasswordForm()
    otp_data: Dict = session.get("otp_data", {})

    # Redirect to 'verify_otp' if otp_data verified is False
    if otp_data.get("verified", None) is None:
        username, email = session.get("username"), session.get("email")
        flash("You need to verify your email before setting a password.", "warning")
        logger.warning(f"User {username} with email {email} attempted to set password for account creation without verified email.")
        return redirect(url_for("signup_auth_bp.verify_otp"))

    if request.method == "POST":
        action: str = request.form.get("action")

        # Handle if pressed 'Back'
        if action == "back":
            # Redirect to 'initial_signup'
            return redirect(url_for("signup_auth_bp.initial_signup"))

        if action == "signup" and form.validate_on_submit():
            # Retrieve & sanitise provided password
            # Retrieve stored username and email
            # Hash inputted password
            password: str = clean_input(form.password.data, False)
            username: Optional[str] = session.get("username")
            email: Optional[str] = session.get("email")
            hashed_password: Optional[str] = generate_password_hash(password)

            try:
                # Create new member
                member: Optional[Member] = Member.create(username=username, email=email, password_hash=hashed_password)

                # Member account creation unsuccessful
                if not member:
                    raise Exception("Failed to create member account.")

                # Member account creation successful
                set_session_data({"signup_stage": "additional_info"})
                flash("Account created successfully. Please continue.", "success")
                logger.info(f"Member account created for user {username} with email {email}.")
                return redirect(url_for("signup_auth_bp.additional_info"))

            # Handle failed account creation
            except Exception as e:
                flash("Account creation failed. Please try again.", "error")
                logger.error(f"Failed to create member account for username: {username}, email: {email}")
                return redirect(url_for("signup_auth_bp.set_password"))

    # Handle GET request, POST request w/o proper action
    return render_template("authentication/signup/set_password.html", form=form)


# Additional info route (Phone number, address, postal code)
@signup_auth_bp.route("/signup/additional_info", methods=["POST", "GET"])
@session_required(["username", "email"])
def additional_info():
    """Capture additional user information after account creation."""
    # If signup_stage in session != "additional_info", redirect to correct stage
    if session.get("signup_stage") != "additional_info":
        return signup_stage_redirect("additional_info")

    # Create form to render
    form: PhoneAddressForm = PhoneAddressForm()

    # Get member info from session
    # Get member object from database based on member info
    username: Optional[str] = session.get("username")
    email: Optional[str] = session.get("email")
    member: Optional[Member] = Member.query.filter_by(username=username, email=email).first()

    # Handle 'member' object not found (no setting password done)
    if not member:
        flash("We couldn't find your account. Please restart the signup process", "error")
        logger.error("Member not found for username: {username}, email{email} when trying to submit additional info.")
        return redirect(url_for("signup_auth_bp.initial_signup"))

    if request.method == "POST":
        # Get action type to respond accordingly
        action: Optional[str] = request.form.get("action")

        # Handle 'skip' action
        if action == "skip":
            # 'member' exists, log member in
            flash("Logged in successfully.", "success")
            logger.info(f"Member {username} logged in without providing additional info.")
            login_user(member)

        # Handle 'complete' action
        if action == "complete":
            if not form.validate_on_submit():
                return render_template("authentication/signup/additional_info.html", form=form)

            try:
                # 'member' exists, inputted data validated, save additional info
                member.phone_number= clean_input(form.phone_number.data)
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
                print("error")

                return redirect(url_for("signup_auth_bp.additional_info"))
    
        # Remove temporary session data (otp_data), retain username and email for logging in
        clear_session_data(["otp_data", "signup_stage"])

        # Redirect to homapge upon successful handling of 'skip' and 'complete' actions
        # TODO: Redirect to standard member homepage
        # return redirect(url_for("member_bp.home"))
        return "Extra info saved, redirect to homepage"

    return render_template("authentication/signup/additional_info.html", form=form)
