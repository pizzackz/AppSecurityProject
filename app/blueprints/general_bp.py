import requests
import logging
from flask import Blueprint, render_template, request, session, redirect, flash, url_for, jsonify
from flask_login import login_required, current_user, logout_user
from flask_jwt_extended import unset_jwt_cookies
from flask_limiter.errors import RateLimitExceeded
from app import db
from app.models import User

# Initialise variables
general_bp = Blueprint('general_bp', __name__)
logger = logging.getLogger("tastefully")


@general_bp.route('/')
def home():
    user = current_user
    try:
        account_type = user.type
        if account_type == 'member':
            return render_template('member/home.html')
        elif account_type == 'admin':
            return render_template('admin/home.html')
    except AttributeError:
        return redirect(url_for('login_auth_bp.login'))


# Logout route
@general_bp.route("/logout")
def logout():
    # Display logout messages    
    flash("You have been successfully logged out!", "success")
    logger.info(f"User '{current_user.username}' has been logged out successfully.")

    # Log user out
    current_user.login_details.logout()
    logout_user()

    # Remove any jwt cookies stored
    response = redirect(url_for("general_bp.home"))
    unset_jwt_cookies(response)

    return response


@general_bp.route('/about')
def about():
    return render_template('about.html')


# Page not Found
@general_bp.errorhandler(404)
def page_not_found(e):
    return render_template('error/error_404.html'), 404


# Internal Server Error
@general_bp.errorhandler(500)
def internal_server_error(e):
    return render_template('error/error_500.html'), 500


# Unauthorized
@general_bp.errorhandler(401)
def unauthorized(e):
    return render_template('error/error_401.html'), 401


# Forbidden
@general_bp.errorhandler(403)
def forbidden(e):
    return render_template('error/error_403.html'), 403


@general_bp.errorhandler(RateLimitExceeded)
def rate_limit_exceeded(e):
    if request.endpoint == 'recipe-creator-ai':
        return jsonify({'content': 'Please wait for a moment before making another request.'}), 429