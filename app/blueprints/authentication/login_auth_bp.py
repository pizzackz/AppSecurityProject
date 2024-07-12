import logging

from logging import Logger
from flask import Blueprint, request, session, redirect, render_template, flash, url_for
from flask_login import login_user
from typing import Union

from app import db, login_manager
from app.models import User, Member, Admin
from app.forms.auth_forms import LoginForm, OtpForm
from app.utilities.utils import clean_input, generate_otp, send_otp_email


login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__, url_prefix="/login")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER = "authentication/login"


# User loader function to retrieve user object from database
@login_manager.user_loader
def load_user(user_id: int) -> Union[User, Member, Admin]:
    user_id = int(user_id)
    user: User = User.query.get(user_id)

    if user.type == "member":
        return Member.query.get(user_id)
    elif user.type == "admin":
        return Admin.query.get(user_id)
    
    return user
