import bleach
import logging

from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_login import login_user
from flask_session import Session
from werkzeug.security import generate_password_hash
from typing import Optional

from app import db
from app.models import User, Member, Admin
from app.forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.email_utils import generate_otp, send_otp_email

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

auth_bp: Blueprint = Blueprint("auth_bp", __name__)


def clean_input(data: str, strip: bool = True) -> str:
    """Sanitise and strip input data using bleach.

    Args:
        data (str): The input data to clean.

    Returns:
        str: The cleaned data.
    """
    if not strip:
        return bleach.clean(data)

    return bleach.clean(data.strip())


# Initial signup route
@auth_bp.route("/signup", methods=["POST", "GET"])
def initial_signup():
    """Handle initial signup by asking for username and email, and send OTP to email provided."""
    # Create form to render
    form = InitialSignupForm()

    if request.method == "POST":
        # Handle validated form, input data sanitised before validation
        if form.validate_on_submit():
            # Sanitise inputs
            username: str = clean_input(form.username.data)
            email: str = clean_input(form.email.data)

            # Store username & email in session for later
            session["username"], session["email"] = username, email

            # Gemerate & Store OTP
            otp: str = generate_otp()
            session["otp"] = otp

            # Send OTP email
            if send_otp_email(email, otp):
                flash("An OTP has been sent to your email.", "info")
                return redirect(url_for("auth_bp.verify_otp"))
            else:
                flash("Failed to send OTP. Please try again.", "danger")

    return render_template("authentication/initial_signup.html", form=form)


# OTP verification route
@auth_bp.route("/verify_otp", methods=["POST", "GET"])
def verify_otp():
    """Verify the OTP sent to user's email."""
    # If no 'username' or 'email' or 'otp' in session, redirect to initial signup
    if not session.get("username") or not session.get("email") or not session.get("otp"):
        flash("Session expired or invalid access. Please start again.", "warning")
        return redirect(url_for("auth_bp.initial_signup"))

    # Create form to render
    form: VerifyOtpForm = VerifyOtpForm()

    if request.method == "POST":
        if form.validate_on_submit():
            # Retrieve OTP from form
            input_otp: str = clean_input(form.otp.data)
            stored_otp: str = session.get("otp")
            
            # Compare OTPs
            if input_otp == stored_otp:
                # OTP matches, proceed to set password
                session.pop("otp")  # Remove OTP from session
                flash("OTP verified successfully. Please set your password", "success")
                return redirect(url_for("auth_bp.set_password"))
            
            flash("Invalid OTP. Please try again.", "danger")
    
    return render_template("authentication/verify_otp.html", form=form)


# Set password route (For initial signups)
@auth_bp.route("/set_password", methods=["POST", "GET"])
def set_password():
    """Allow member user to set a password after OTP verification."""
    # If no 'username' or 'email' in session, redirect to initial signup
    if not session.get("username") or not session.get("email"):
        flash("Session expired or invalid access. Please start again.", "warning")
        return redirect(url_for("auth_bp.initial_signup"))

    # Create form to render
    form: SetPasswordForm = SetPasswordForm()

    if request.method == "POST":
        if form.validate_on_submit():
            # Retrieve provided password
            password: str = clean_input(form.password.data, False)
            hashed_password: str = generate_password_hash(password)  # Hash inputted password

            # Retrieve stored username and email
            username: str = session.get("username")
            email: str = session.get("email")

            if username and email:
                # Check whether account already exists
                user = User.query.filter_by(username=username, email=email).first()

                # TODO: Redirect to login if user found
                if user:
                    flash("User already exists. Please login.", "info")
                    # return redirect(url_for("auth_bp.login"))
                    return "User exists, please login now"

                # Create new member
                member: Member = Member.create(username=username, email=email, password_hash=hashed_password)

                if member:
                    flash("Account created successfully. Please continue.", "success")
                    # TODO: Redirect to prompt for additional info (phone num, address...)
                    return redirect(url_for("auth_bp.additional_info"))
                
                # Handle failed account creation
                flash("Account creation failed. Please try again.", "danger")
                logger.error(f"Failed to create member account for username: {username}, email: {email}")

            flash("An error occurred. Please try again.", "danger")

    return render_template("authentication/set_password.html", form=form)


# TODO - Allow skipping of this step (meaning no updating member model), redirect straight to homepage
# TODO - Complete HTML template(s) required
# Additional info route (Phone number, address, postal code)
@auth_bp.route("/additional_info", methods=["POST", "GET"])
def additional_info():
    """Capture additional user information after account creation."""
    # If no 'username' or 'email' in session, redirect to initial signup
    if not session.get("username") or not session.get("email"):
        flash("Session expired or invalid access. Please start again.", "warning")
        return redirect(url_for("auth_bp.initial_signup"))
    
    # Create form to render
    form: PhoneAddressForm = PhoneAddressForm

    if request.method == "POST":
        if form.validate_on_submit():
            # Retrieve member info from session
            username: str = session.get("username")
            email: str = session.get("email")
            
            # Retrieve member from database
            member: Optional[Member] = Member.query.filter_by(username=username, email=email).first()

            # If 'member' exists, update additional info based on sanitised input data
            if member:
                member.phone_number = clean_input(form.phone_number.data)
                member.address = clean_input(form.address.data)
                member.postal_code = clean_input(form.postal_code)
                db.session.commit()

                flash("Additional information saved successfully.", "success")

                # TODO: Redirect to homepage
                # return redirect(url_for("member_bp.home"))
                return "Extra info saved, redirect to homepage"
            
            flash("User not found. Please start again.", "danger")
            session.pop("username")
            session.pop("email")
            
            return redirect(url_for("auth_bp.initial_signup"))
    
    return render_template("authentication/additional_info.html", form=form)
