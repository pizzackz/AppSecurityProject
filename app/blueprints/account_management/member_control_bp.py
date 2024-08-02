# To deal with administrative actions on member accounts comprising of RUD of CRUD
# Provides an interface primarily to view all/specific members
# Admins only allowed through proper verified admin accounts and actions are preceeded with
# admin key verification
# Allowed administrative actions - View all/specific member, Lock member, delete member account,
# revoke subscription
import logging
import hashlib

from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Optional, Set

from flask import Blueprint, request, session, redirect, render_template, flash, url_for, make_response, Response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash

from app import db
from app.models import Admin, MasterKey, LockedAccount, PasswordResetToken
from app.forms.forms import CreateAdminForm, LockAdminForm, DeleteAdminForm
from app.forms.auth_forms import OtpForm
from app.utils import logout_if_logged_in, clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_session_keys, check_expired_session, set_session_data, check_auth_stage, check_jwt_values, get_image_url


# Initialise variables
admin_control_bp = Blueprint("admin_control_bp", __name__, url_prefix="/start")
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "account_management/member"
ESSENTIAL_KEYS = {'_user_id', '_fresh', '_id'}
MEMBER_SPECIFIC_ESSENTIAL_KEYS = {'_user_id', '_fresh', '_id', "member_id"}