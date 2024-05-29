from flask import Blueprint, render_template, session, url_for, flash, redirect, request
from flask_login import login_user


admin_log: Blueprint = Blueprint("admin_log", __name__)



@admin_log.route("/dashboard")
def dashB():
    return render_template("admin_dashboard_bp.py")


@admin_log.route("")

