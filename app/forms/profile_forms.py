from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import Form, StringField, FileField, TelField
from wtforms.validators import Length, Optional

from app.forms.validators import validate_phone_number, validate_postal_code, validate_file_size_limit
from app import profile_pictures


# Main member profile form to display all fields
class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[Optional(), Length(min=2, max=20)])
    email = StringField("Email")
    phone_number = TelField('Phone Number', validators=[Optional(), validate_phone_number])
    address = StringField('Address', validators=[Optional(), Length(min=1, max=150)])
    postal_code = TelField('Postal Code', validators=[Optional(), Length(max=20), validate_postal_code])
    profile_picture = FileField("", validators=[
        Optional(),
        FileAllowed(profile_pictures, "Only image files with these extensions are allowed: (jpg, jpeg, png, gif)"),
        validate_file_size_limit(5 * 1024 * 1024)
    ])
