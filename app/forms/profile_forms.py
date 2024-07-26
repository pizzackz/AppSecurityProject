from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import Form, StringField, FileField, TelField
from wtforms.validators import Length, Optional

from app.forms.validators import validate_phone_number, validate_postal_code, validate_image


# Main member profile form to display all fields
class MemberProfileForm(FlaskForm):
    username = StringField("Username", validators=[Optional(), Length(min=2, max=20)])
    email = StringField("Email")
    phone_number = TelField('Phone Number', validators=[Optional(), validate_phone_number])
    address = StringField('Address', validators=[Optional(), Length(min=1, max=150)])
    postal_code = TelField('Postal Code', validators=[Optional(), Length(max=20), validate_postal_code])


