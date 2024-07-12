import logging

from logging import Logger
from flask import Blueprint, request, redirect, render_template, url_for, flash, session

from app.models import User
from app.forms.auth_forms import EmailForm, OtpForm, RecoverOptionsForm
from app.utilities.utils import clean_input, generate_otp, send_otp_email


# Initialise flask blueprint - 'login_aut_bp'
recovery_auth_bp: Blueprint = Blueprint("recovery_auth_bp", __name__, url_prefix="/recovery")
logger: Logger = logging.getLogger('tastefully')
TEMPLATE_FOLDER = "authentication/recovery"
