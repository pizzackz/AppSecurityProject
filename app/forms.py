from wtforms import Form, StringField, PasswordField, FileField, TextAreaField, IntegerField, SelectField, DecimalField
from wtforms.validators import Email, DataRequired, Length, NumberRange
from validators import unique_data, password_complexity, data_exist, otp_validator, six_digit_postal_code_validator, phone_number_validator, card_number_validator, card_expiry_validator


class CreateRecipeForm(Form):
    name = StringField("Name", validators=[DataRequired(), Length(max=255)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()], render_kw={"class": "form-control"})
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})

