import requests
import logging
from flask import Blueprint, render_template, request, session, redirect, flash, url_for, jsonify, make_response
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
            return redirect(url_for('general_bp.member_home'))
        elif account_type == 'admin':
            return redirect(url_for('general_bp.admin_home'))
    except AttributeError:
        return render_template('guest/home.html')

@general_bp.route('/home')
@login_required
def member_home():
    account_type = current_user.type
    if account_type == 'admin':
        return redirect(url_for('general_bp.admin_home'))
    return render_template('member/home.html')

@general_bp.route('/admin/home')
@login_required
def admin_home():
    account_type = current_user.type
    if account_type == 'member':
        return redirect(url_for('general_bp.member_home'))
    return render_template('admin/home.html')


# Logout route
@general_bp.route("/logout")
def logout():
    if current_user.is_authenticated:
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


# Bad request
@general_bp.errorhandler(400)
def bad_request(e):
    session.clear()
    response = make_response(render_template("authentication/login.html"))
    unset_jwt_cookies(response)
    flash("An error occurred. Please try again!", "error")
    return response


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