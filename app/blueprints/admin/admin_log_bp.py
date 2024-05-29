from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_login import login_user


admin_log_bp: Blueprint = Blueprint("admin_log", __name__)



@admin_log_bp.route("/dashboard")
def dashB():
    # return render_template("admin_dashboard_bp.py")  # You're supposed to render a template (i.e. HTML file), not a python file
    return render_template("admin/logging/dashboard.html")


# @admin_log_bp.route("")

