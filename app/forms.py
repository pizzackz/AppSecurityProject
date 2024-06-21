from wtforms import Form, StringField, PasswordField, FileField, TextAreaField, IntegerField, SelectField, DecimalField, SubmitField, validators, HiddenField
from wtforms.validators import Email, DataRequired, Length, NumberRange, Optional, EqualTo
from flask_wtf import FlaskForm

from app.form_validators import unique_email, unique_username, validate_email_format, validate_otp, validate_password_complexity, validate_phone_number, validate_postal_code, six_digit_postal_code_validator, phone_number_validator


# Signup related forms to accomodate different phases of signing up
# Manual Signup phase 1 form, requires username & email
class InitialSignupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20), unique_username])
    email = StringField("Email", validators=[DataRequired(), validate_email_format, unique_email])


# Manual Signup phase 2 - Verify email using otp
class VerifyOtpForm(FlaskForm):
    otp = StringField("One Time Code", validators=[DataRequired(), Length(min=6, max=6), validate_otp])


# Manual Signup & 1st time google signin - Set password
class SetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6), validate_password_complexity])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])


# Signup optional fields - Save phone & address
class PhoneAddressForm(FlaskForm):
    phone_number = StringField('Phone', [phone_number_validator, Optional()],render_kw={"placeholder": "E.g. 9123 4567"})
    address = StringField('Address', [Length(min=1, max=150), Optional()], render_kw={"placeholder": "E.g. 123 ABC Street"})
    postal_code = StringField('Postal Code', [six_digit_postal_code_validator, Optional()], render_kw={"placeholder": "E.g. 123456"})


# Create recipe form for members and admin, can double as Update recipe form
class CreateRecipeForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=20)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()])
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})
    calories = IntegerField("Calories", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    prep_time = IntegerField("Preparation Time (minutes)", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    recipe_type = SelectField("Type", choices=[("Standard", "Standard"), ("Premium", "Premium")], validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Create Recipe", render_kw={"class": "btn btn-primary"})


class RecipeSearch(FlaskForm):
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Search", render_kw={"class": "btn btn-primary"})


class createFeedback(Form):
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
