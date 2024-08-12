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
    jsonify
)
from flask_login import login_required, current_user
from app.models import Feedback
from app import db

admin_feedback_bp = Blueprint("admin_feedback_bp", __name__)

@admin_feedback_bp.route("/admin/feedback")
@login_required
def admin_feedback():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    
    feedbacks = Feedback.query.all()
    return render_template("admin/feedback/admin_feedback.html", feedbacks=feedbacks)

@admin_feedback_bp.route('/admin/delete_feedback/<int:feedback_id>', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    
    print(feedback_id)
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted successfully", "success")
    return redirect(url_for("admin_feedback_bp.admin_feedback"))