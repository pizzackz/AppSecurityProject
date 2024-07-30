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
from flask_login import login_required
from bleach import clean
from app.models import Feedback
from app import db

from app.forms.forms import CreateFeedback

member_feedback_bp = Blueprint("member_feedback_bp", __name__)


@member_feedback_bp.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    feedback_form = CreateFeedback()
    if request.method == 'POST' and feedback_form.validate_on_submit():
        #sanitise name
        name = clean(feedback_form.name.data)

        #ensure category is valid
        valid_categories = ["product", "website", "delivery", "others"]
        category = feedback_form.category.data
        if category not in valid_categories:
            flash('Invalid category selection.', 'danger')
            return render_template('feedback.html', form=feedback_form)
        
        #ensure rating is valid
        try:
            rating = float(feedback_form.rating.data)
            if not (1 <= rating <= 5):
                flash('Rating must be between 1 and 5.', 'danger')
                return render_template('feedback.html', form=feedback_form)
        except ValueError:
            flash('Invalid rating value.', 'danger')
            return render_template('feedback.html', form=feedback_form)
        
        #sanitise comment
        comment = clean(feedback_form.comment.data)


        # Storing in database
        new_feedback = Feedback(name=name, category=category, rating=rating, comment=comment)
        try:
            db.session.add(new_feedback)
            db.session.commit()
            flash('Feedback successfully submitted!', 'success')
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
