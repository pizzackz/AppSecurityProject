import logging

from logging import Logger
from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from werkzeug.security import generate_password_hash

from app import db
from app.models import Member
from app.forms.auth_forms import SignupForm, OtpForm, PasswordField, ExtraInfoForm
from app.utilities.utils import clean_input, generate_otp, send_email


signup_auth_bp: Blueprint = Blueprint("signup_auth_bp", __name__, url_prefix="/signup")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER: str = "authentication/signup"


