from wtforms import Form, StringField, FileField, TextAreaField, IntegerField, SelectField, DecimalField, SubmitField, validators, HiddenField
from wtforms.validators import DataRequired, Length, NumberRange
from flask_wtf import FlaskForm

from app.forms.validators import six_digit_postal_code_validator, phone_number_validator


# Create recipe form for members and admin, can double as Update recipe form
class CreateRecipeForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=20)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()])
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})
    calories = IntegerField("Calories", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    prep_time = IntegerField("Preparation Time (minutes)", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    recipe_type = SelectField("Type", choices=[("Standard", "Standard"), ("Premium", "Premium"), ("Private", "Private")], validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Create Recipe", render_kw={"class": "btn btn-primary"})


class RecipeSearch(FlaskForm):
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Search", render_kw={"class": "btn btn-primary"})


class CreateFeedback(Form):
    name = StringField('Your Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    category = SelectField('Category', choices=[("product", "Product"), ("website", "Website"), ("delivery", "Delivery"), ("others", "Others")])
    rating = DecimalField('Overall Satisfaction', [validators.NumberRange(min=1, max=5)])
    comment = TextAreaField('Feedback', [validators.DataRequired()])


# Order form to order menu items
class MenuForm(FlaskForm):
    menu_item_id = HiddenField()
    submit = SubmitField("Order")


class OrderForm(FlaskForm):
    menu_item_id = HiddenField()
    name = StringField('Name', [Length(min=1, max=150), DataRequired()], render_kw={"placeholder": "John Doe"})
    address = StringField('Address', [Length(min=1, max=150), DataRequired()], render_kw={"placeholder": "123 ABC Street"})
    postal_code = StringField('Postal Code', [six_digit_postal_code_validator, DataRequired()], render_kw={"placeholder": "123456"})
    phone_number = StringField('Phone', [phone_number_validator, DataRequired()], render_kw={"placeholder": "9123 4567"})
    selected_date = HiddenField('Selected Date', validators=[DataRequired()])
    selected_time = HiddenField('Selected Time', validators=[DataRequired()])
    submit = SubmitField('Schedule Delivery')
