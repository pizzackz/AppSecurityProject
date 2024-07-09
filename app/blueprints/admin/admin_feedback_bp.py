from flask import (
    Flask,
    current_app,
    Blueprint,
    render_template,
    request,
    redirect,
    session,
    flash,
    url_for,
)
from app.models import Feedback
from app import db

admin_feedback_bp = Blueprint("admin_feedback_bp", __name__)

@admin_feedback_bp.route("/admin/feedback")
def admin_feedback():
    feedback = Feedback.query.all()
    print(feedback)
    return render_template("admin/feedback/admin_feedback.html", feedback=feedback)