from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField
from wtforms.validators import DataRequired, Length, Optional, EqualTo

from app.forms.validators import validate_password_complexity, validate_phone_number, validate_postal_code


# Main member profile form to display all fields
class MemberProfileForm(FlaskForm):
    username = StringField("Username", validators=[Optional(), Length(min=2, max=20)])
    email = StringField("Email")
    phone_number = StringField('Phone Number', validators=[Optional(), validate_phone_number])
    address = StringField('Address', validators=[Optional(), Length(min=1, max=150)])
    postal_code = StringField('Postal Code', validators=[Optional(), Length(max=20), validate_postal_code])


# Change password form
class ChangePasswordForm(FlaskForm):
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=8), validate_password_complexity])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), Length(min=8), EqualTo("new_password", "Passwords must match")])

