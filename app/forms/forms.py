from wtforms import Form, StringField, FileField, TextAreaField, IntegerField, SelectField, DecimalField, SubmitField, validators, HiddenField, DateField, TimeField, PasswordField
from wtforms.validators import DataRequired, Length, NumberRange, Regexp, EqualTo
from flask_wtf import FlaskForm, RecaptchaField

from app.forms.validators import validate_email_format, unique_username, unique_email, six_digit_postal_code_validator, phone_number_validator


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


class CreateRecipeFormMember(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=20)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()])
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})
    calories = IntegerField("Calories", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    prep_time = IntegerField("Preparation Time (minutes)", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    recipe_type = SelectField("Type", choices=[("Standard", "Standard"), ("Private", "Private")], validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Create Recipe", render_kw={"class": "btn btn-primary"})


class RecipeSearch(FlaskForm):
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Search", render_kw={"class": "btn btn-primary"})


class AICreateRecipeForm(FlaskForm):
    cuisine = StringField("Cuisine", validators=[Length(max=12)], render_kw={'class': 'form-control'})
    ingredients = StringField('Ingredients', render_kw={"class": "form-control m-2"})
    dietary_preference = StringField('Dietary Preference', validators=[Length(max=15)], render_kw={'class:': 'form-control'})
    allergy = StringField('Allergy', validators=[Length(max=10)], render_kw={'class:': 'form-control'})
    meal_type = StringField('Meal type', validators=[Length(max=10)], render_kw={'class:': 'form-control'})
    difficulty = SelectField('Difficulty', choices=[("easy", "Easy"), ("medium", "Medium"), ("hard", "Hard"), ('any', 'Any')], render_kw={"class": "form-control m-2"})
    remarks = TextAreaField('Remarks', render_kw={"class": "form-control m-2"})

    """
    cuisine = request.json.get('cuisine')
    ingredients = request.json.get('ingredients')
    dietary_preference = request.json.get('dietary_preference')
    allergy = request.json.get('allergy')
    meal_type = request.json.get('meal_type') (Dropdown field
    difficulty = request.json.get('difficulty')
    remarks = request.json.get('remarks')
    """


class CreateFeedback(FlaskForm):
    name = StringField('Your Name', [validators.Length(min=1, max=150), validators.DataRequired(), Regexp(r'^[a-zA-Z]+$', message="Name must contain only letters.")])
    category = SelectField('Category', choices=[("product", "Product"), ("website", "Website"), ("delivery", "Delivery"), ("others", "Others")])
    rating = DecimalField('Overall Satisfaction', [validators.NumberRange(min=1, max=5)])
    comment = TextAreaField('Feedback', [validators.DataRequired(), validators.Length(max=500)])


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
    selected_date = DateField('Delivery Date', [validators.DataRequired()], format='%Y-%m-%d')
    selected_time = TimeField('Delivery Time', [validators.DataRequired()], format='%H:%M')
    selected_items = StringField('Selected Items', [validators.DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Schedule Delivery')


# Create admin form
class CreateAdminForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20), unique_username])
    email = StringField("Email", validators=[DataRequired(), validate_email_format, unique_email])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), Length(min=8), EqualTo("password", "Passwords must match")])
    recaptcha = RecaptchaField()

# Lock admin form
class LockAdminForm(FlaskForm):
    reason = TextAreaField("Reason for Locking", validators=[DataRequired()])
    recaptcha = RecaptchaField()


# Delete admin form
class DeleteAdminForm(FlaskForm):
    master_key = StringField("Re-enter Master Key", validators=[DataRequired()])
    recaptcha = RecaptchaField()


# Lock or Delete member form
class LockDeleteMemberForm(FlaskForm):
    reason = TextAreaField("Reason", validators=[DataRequired()])
    admin_key = StringField("Enter Admin Key", validators=[DataRequired()])
    recaptcha = RecaptchaField()


# Create forum post
class ForumPost(FlaskForm):
    title = StringField('Title', validators=[validators.DataRequired(), validators.Length(max=50)])
    body = TextAreaField('Body', validators=[validators.DataRequired(), validators.Length(max=1000)])


class PostComment(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired(), validators.Length(max=500)])