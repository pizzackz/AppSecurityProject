# To deal with creation, retrieval of read-only data, & deletion of admin accounts
# Provides a highly secured web interface to allow CRD for admin accounts
import logging
import hashlib
import os

from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Union, Dict, Optional

from flask import Blueprint, request, session, redirect, render_template, flash, url_for, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash
from google_auth_oauthlib.flow import Flow

from app import db, jwt
from app.config.config import Config
from app.models import User, Admin, MasterKey
from app.forms.auth_forms import LoginForm, OtpForm, ConfirmNewMemberForm, ConfirmGoogleLinkForm
from app.utils import clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_auth_stage, check_jwt_values


# Initialise variables
admin_control_bp = Blueprint("admin_control_bp", __name__, url_prefix="/start")
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "account_management/admin"


# Initial route to authroise "admin" user into admin control pages using master key
@admin_control_bp.route("/", methods=['GET', 'POST'])
def start():
    # Clear all session data and jwt tokens
    clear_unwanted_session_keys()

    if request.method == "POST":
        print(request.form)
        form_data = request.form.get("master_key")

        # Check if have input
        if not form_data:
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response

        # Sanitise input
        master_key_input = clean_input(form_data)

        # Check if input has exactly length of 64 characters
        if len(form_data) != 64:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter a fake admin key with length of '{len(form_data)}' characters.")
            response = redirect(url_for("admin_control_bp.start"))
            return response

        # Check if have existing master key record of same value
        master_key_record = MasterKey.query.filter_by(value=master_key_input).first()
        if not master_key_record:
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter admin control without having correct master key.")
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response
        
        # Check if master key is outdated/ expired
        if master_key_record.expires_at <= datetime.now():
            flash("Invalid master key!", "error")
            logger.warning(f"A user tried to enter admin control using an expired master key.")
            response = redirect(url_for("admin_control_bp.start"))
            unset_jwt_cookies(response)
            return response

        # Create & store session data
        session_data = {
            "id": master_key_record.id,
            'expires_at': master_key_record.expires_at,
            'session_expiry': datetime.now(timezone.utc) + timedelta(minutes=30)
        }
        session["master_key"] = session_data

        response = redirect(url_for("admin_control_bp.start_1"))
        unset_jwt_cookies(response)
        return response

    response = make_response(render_template(f"{TEMPLATE_FOLDER}/start.html"))
    unset_jwt_cookies(response)
    return response


# Admin control dashboard route for viewing all admin accounts
@admin_control_bp.route("/1", methods=['GET', 'POST'])
def start_1():
    return "This is the admin control dashboard"
