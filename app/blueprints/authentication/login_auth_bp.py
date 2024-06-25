import logging

from logging import Logger
from flask import Blueprint, request, redirect, render_template, url_for

from app import db
from app.models import User
# from app.forms.forms import InitialLoginForm


# Initialise flask blueprint - 'login_aut_bp'
login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__)

# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Initial login route
@login_auth_bp.route("/login", methods=["POST", "GET"])
def initial_login():
    # Create form to render
    # form: InitialLoginForm = InitialLoginForm()

    if request.method == "POST":
        # TODO: Initial login processes
        # TODO: Redirect to appropriate homepages
        # return redirect(url_for("member.member_homepage"))
        # return redirect(url_for("admin.admin_homepage"))
        return "Redirecting to appropriate homepage..."
    
    # TODO: GET request processes
    return render_template("authentication/login/initial_login.html", form=form)
        
