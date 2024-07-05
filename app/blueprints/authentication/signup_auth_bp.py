import logging
import hashlib

from logging import Logger
from datetime import datetime
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.utils import clean_input, generate_otp, send_otp_email, session_required, clear_session_data, set_session_data, validate_otp_data

signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__)

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Initial signup route
@signup_auth_bp.route("/signup", methods=["POST", "GET"])
def signup():
    """Handle initial signup by asking for username & email, then send OTP to email provided."""

    # Create form to render
    form = InitialSignupForm()

    # Handle POST request
    # Handle validated form
    if request.method == "POST" and form.validate_on_submit():
        # Get & sanitise inputs
        username = clean_input(form.username.data)
        email = clean_input(form.email.data)

        # Store data in session for future stages & sending of OTP
        set_session_data({
            "username": username,
            "email": email,
            "signup_stage": "otp"
        })
        
        return redirect(url_for("signup_auth_bp.send_otp"))
    
    return render_template("authentication/signup/initial_signup.html", form=form)


# Resend OTP route
@signup_auth_bp.route("/signup/send_otp", methods=["GET"])
def send_otp():
    """Resend the OTP to the user's email."""
    # Retrieve username & email from session
    username = session.get("username")
    email = session.get("email")

    # Generate OTP & current time
    otp = generate_otp()
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    current_time = datetime.now()
    otp_data = {
        "value": otp_hash,
        "gen_time": current_time.strftime("%d/%b/%Y %H:%M:%S"),
        "verified": False
    }

    # Store data in session for future stages
    set_session_data({
        "username": username,
        "email": email,
        "otp_data": otp_data,
        "signup_stage": "otp"
    })

    # Send OTP email
    if send_otp_email(email, otp):
        flash("An OTP has been sent to your email.", "info")
        logger.info(f"OTP sent to {email} for user {username}.")
    else:
        flash("Failed to  OTP. Please try again.", "error")
        logger.error(f"Failed to resend OTP to {email} for user {username}")

    return redirect(url_for("signup_auth_bp.verify_otp"))


# OTP verification route
@signup_auth_bp.route("/signup/verify_otp", methods=["POST", "GET"])
def verify_otp():
    """Verify the OTP sent to user's email."""

    # Create form to render
    form = VerifyOtpForm()

    # Handle POST data
    # Handle validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & sanitise OTP from form
        input_otp = clean_input(form.otp.data)

        # Check OTP length
        if not len(input_otp) == 6:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP length attempt for user {session['username']} with email {session['email']}.")

        # Hash inputted data & Retrieve OTP from session
        hashed_input_otp = hashlib.sha256(input_otp.encode()).hexdigest()
        otp_data = session.get("otp_data")

        # Validate otp_data
        required_keys = ["value", "gen_time", "verified"]
        if not validate_otp_data(otp_data, required_keys, expiry_time=5):
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid or expired OTP attempt for user {session['username']} with email {session['email']}")
            return redirect(url_for("signup_auth_bp.verify_otp"))
        
        # Compare OTPs
        if hashed_input_otp != otp_data.get("value"):
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user {session['username']} with email {session['email']}.")
            return redirect(url_for("signup_auth_bp.verify_otp"))
        
        # OTP matches, update verification status & time, proceed to set password
        otp_data["verified"] = True
        set_session_data({"otp_data": otp_data, "signup_stage": "password"})

        flash("Email verified successfully. Please set your password", "success")
        logger.info(f"OTP verified for user {session['username']} with email {session['email']}.")
        return redirect(url_for("signup_auth_bp.set_password"))
    
    return render_template("authentication/signup/verify_otp.html", form=form)


# Set password route (for manual signups)
@signup_auth_bp.route("/signup/set_password", methods=["POST", "GET"])
def set_password():
    """Allow member user to set a password after OTP verification"""

    # Create form to render
    form = SetPasswordForm()

    # Handle POST request
    # Handle validated form
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve username & email from session
        username, email = session.get("username"), session.get("email")

        # Hash inputted password
        password = form.password.data
        password_hash = generate_password_hash(password)

        # Create member with retrieved credentials
        try:
            member = Member.create(username=username, email=email, password_hash=password_hash)

            # Unsuccessful account creation
            if not member:
                raise Exception("Failed to create member account.")
            
            # Successful account creation
            set_session_data({"signup_stage": "extra_info"})
            flash("Account created successfully. Please continue.", "success")
            logger.info(f"Member account created for user {username} with email {email}.")
            return redirect(url_for("signup_auth_bp.extra_info"))
        
        # Handle failed account creation
        except Exception as e:
            flash("Account creation failed. Please try again.", "error")
            logger.error(f"Failed to create member account for username: {username}, email: {email}")
            return redirect(url_for("signup_auth_bp.set_password"))

    return render_template("authentication/signup/set_password.html", form=form)


# Extra info route (to get Phone number, Address, Postal code)
@signup_auth_bp.route("/signup/extra_info", methods=["POST", "GET"])
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
        logger.error("Member not found for username: {username}, email{email} when trying to submit extra info.")
        return redirect(url_for("signup_auth_bp.initial_signup"))
    
    # Handle POST request
    if request.method == "POST":
        # Retrieve action to respond accordingly
        action = request.form.get("action")

        # Handle "skip" action
        if action == "skip":
            flash("You can log in now.", "success")
            logger.info(f"No extra info saved for member {username}.")

        # Handle "complete" action
        if action == "complete":
            if not form.validate_on_submit():
                return render_template("authentication/signup/extra_info.html", form=form)

            # Save info to database
            try:
                # Retrieve & sanitise inputs
                phone_number = clean_input(form.phone_number.data)
                address = clean_input(form.address.data)
                postal_code = clean_input(form.postal_code.data)

                # Update only if input provided
                if phone_number:
                    member.phone_number = phone_number
                if address:
                    member.address = address
                if postal_code:
                    member.postal_code = postal_code

                db.session.commit()

                flash("Extra inforamtion saved. You can log in now.", "success")
                logger.info(f"Extra info saved for member {username}.")

            # Handle any exceptions when saving data
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred when trying to save your data. Please try again", "error")
                logger.error(f"Failed to save extra info for user {username}, email {email}. Error: {e}")
                print("error")

                return redirect(url_for("signup_auth_bp.extra_info"))

        # Clear session data
        clear_session_data(["username", "email", "otp_data", "signup_stage"])

        return redirect(url_for("login_auth_bp.login"))
    return render_template("authentication/signup/extra_info.html", form=form)
