import bleach

from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_login import login_user
from flask_session import Session
from werkzeug.security import generate_password_hash

from app import db
from app.models import User, Admin, Member, Authentication
from app.forms import InitialSignupForm, VerifyOtpForm, SetPasswordForm, PhoneAddressForm
from app.email_utils import send_email


auth_bp: Blueprint = Blueprint("auth_bp", __name__)


# Initial signup route
@auth_bp.route("/signup", methods=["POST", "GET"])
def initial_signup():
    form = InitialSignupForm()

    if request.method == "POST":
        # Handle validated form, input data sanitised before validation
        if form.validate_on_submit():
            # Sanitise inputs
            username = bleach.clean(form.username.data.strip())
            email = bleach.clean(form.email.data.strip())

            # Store username & email in session for later
            session["username"], session["email"] = username, email

            success: bool = send_email("Test", "Testing whether email works", email)
            return success

    return render_template("authentication/initial_signup.html", form=form)
