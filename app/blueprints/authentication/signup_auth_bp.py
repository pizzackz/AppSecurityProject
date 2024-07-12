import logging

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_jwt_extended import create_access_token, set_access_cookies, get_jwt, jwt_required
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import SignupForm, OtpForm
from app.utilities.utils import clean_input, generate_otp, hash_otp, send_email, create_jwt_token, decode_jwt_token


signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__, url_prefix="/signup")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER: str = "authentication/signup"


# initial signup route
@signup_auth_bp.route('/', methods=['GET', 'POST'])
def signup():
    """
    Signup route to initiate the user registration process.
    It validates the signup form, cleans inputs, generates an OTP and stores intermediate stage in session.
    """
    form = SignupForm()
    
    if request.method == "POST" and form.validate_on_submit():
        # Clean inputs
        username = clean_input(form.username.data)
        email = clean_input(form.email.data)

        # Create JWT token for sensitive data
        identity = {'email': email, 'username': username}
        token = create_jwt_token(identity=identity)
        set_access_cookies(request, token)

        # Store intermediate stage in session
        session['signup_stage'] = 'otp_sent'

        return redirect(url_for('signup_auth_bp.send_otp'))

    return render_template(f'{TEMPLATE_FOLDER}/signup.html', form=form)


# Send otp route
@signup_auth_bp('/', methods=["GET"])
@jwt_required
def send_otp():
    
