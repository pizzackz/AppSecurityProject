from wtforms import Form, StringField, PasswordField, FileField, TextAreaField, IntegerField, SelectField, DecimalField, SubmitField
from wtforms.validators import Email, DataRequired, Length, NumberRange
# from validators import unique_data, password_complexity, data_exist, otp_validator, six_digit_postal_code_validator, phone_number_validator, card_number_validator, card_expiry_validator
from flask_wtf import FlaskForm


class CreateRecipeForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=20)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()])
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})
    calories = IntegerField("Calories", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    prep_time = IntegerField("Preparation Time (minutes)", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    type = SelectField("Type", choices=[("Standard", "Standard"), ("Premium", "Premium")], validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Create Recipe", render_kw={"class": "btn btn-primary"})

