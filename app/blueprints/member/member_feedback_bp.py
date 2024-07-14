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

from app.forms.forms import CreateFeedback

member_feedback_bp = Blueprint("member_feedback_bp", __name__)


@member_feedback_bp.route("/feedback", methods=["GET", "POST"])
def feedback():
    feedback_form = CreateFeedback()
    if request.method == 'POST' and feedback_form.validate_on_submit():
        name = feedback_form.name.data
        category = feedback_form.category.data
        rating = feedback_form.rating.data
        comment = feedback_form.comment.data


        # Storing in database
        new_feedback = Feedback(name=name, category=category, rating=rating, comment=comment)
        try:
            db.session.add(new_feedback)
            db.session.commit()
        except:
            print('Error in creating feedback')
            flash('An error occurred while creating the feedback. Please try again.', 'danger')
    # if request.method == 'POST' and feedback_form.validate():
    # feedback_dict = {}
    # db = shelve.open('feedback.db', 'c')
    # try:
    #     feedback_dict = db['Feedback']
    # except:
    #     print("Error in retrieving Feedback from feedback.db.")

    # # cust id should be changed to an actual customer id
    # feedback = Feedback(feedback_form.name.data, feedback_form.category.data, feedback_form.rating.data, feedback_form.comment.data, cust_id=1)
    # feedback_dict[feedback.get_id()] = feedback

    # db['Feedback'] = feedback_dict
    # db.close()

    # # change redirect to homepage
    # return redirect(url_for('menu'))
    return render_template("member/feedback/customer_feedback.html", form=feedback_form)
