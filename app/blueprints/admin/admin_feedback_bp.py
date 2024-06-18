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

admin_feedback_bp = Blueprint("admin_feedback_bp", __name__)

@admin_feedback_bp.route("/admin/feedback")
def admin_feedback():
# err what the sigma
    return render_template