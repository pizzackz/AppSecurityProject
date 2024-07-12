from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, RadioField
from wtforms.validators import DataRequired, Length, Optional, EqualTo

from app.forms.validators import unique_email, unique_username, validate_email_format, validate_otp, validate_password_complexity, validate_phone_number, validate_postal_code


# Manual Signup phase 1 form, requires username, email
class SignupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20), unique_username])
    email = StringField("Email", validators=[DataRequired(), validate_email_format, unique_email])


# Manual Login phase 1 form, requires username & password
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])


# Account Recovery Phase 1 - Retrieve account from email
class EmailForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), validate_email_format])


# Manual Signup phase 2 | Manual Login phase 2 | Account Recovery Phase 2 - Verify email using otp
class OtpForm(FlaskForm):
    otp = StringField("One Time Code", validators=[DataRequired(), Length(min=6, max=6), validate_otp])


# Manual Signup phase 3 | 1st time Google Sign-in - Set password for account
class PasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8), validate_password_complexity])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), Length(min=8), EqualTo("password", "Confirm password must be equal to your password")])


# Account Recovery Phase 2 - Choosing to recover username or set new password
class RecoverOptionsForm(FlaskForm):
    recovery_option = RadioField("", choices=[("recover_username", "Recover Username"), ("change_password", "Change Password")], default="username", validate_choice=True)


# Signup optional fields - Save phone & address
class ExtraInfoForm(FlaskForm):
    phone_number = StringField('Phone Number', [validate_phone_number, Optional()],render_kw={"placeholder": "E.g. 9123 4567"})
    address = StringField('Address', [Length(min=1, max=150), Optional()], render_kw={"placeholder": "E.g. 123 ABC Street"})
    postal_code = StringField('Postal Code', [validate_postal_code, Optional()], render_kw={"placeholder": "E.g. 123456"})


# Account Recovery Phase 3 - Set new password
class NewPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=6), validate_password_complexity])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
