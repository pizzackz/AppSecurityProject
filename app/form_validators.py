import re
import bleach
from wtforms import ValidationError
from app.models import User
from email_validator import validate_email, EmailNotValidError


# Function to sanitise data first before validating
def sanitise_data(data: str) -> str:
    sanitised_data = bleach.clean(data)
    return sanitised_data


# Validtor for unique username
def unique_username(form, field):
    if User.query.filter_by(username=sanitise_data(field.data)).first():
        raise ValidationError("Username is already in use. Please choose another one.")
    

# Validator for unique email
def unique_email(form, field):
    if User.query.filter_by(email=sanitise_data(field.data)).first():
        raise ValidationError("Email is already in use. Please choose another one.")


# Validator for email format
def validate_email_format(form, field):
    try:
        validate_email(field.data)
    except EmailNotValidError as e:
        raise ValidationError(str(e))


# Validator for OTP length
def validate_otp(form, field):
    if not sanitise_data(field.data).isdigit() or len(sanitise_data(field.data)) != 6:
        raise ValidationError("OTP must be a 6 digit number.")


# Validators for password complextiy policy
def validate_password_complexity(form, field):
    sanitised_data: str = sanitise_data(field.data)
    errors: list[int] = list()

    errors.append(validate_password_length(form, sanitise_data(field.data)))
    errors.append(validate_password_upper(form, sanitise_data(field.data)))
    errors.append(validate_password_lower(form, sanitise_data(field.data)))
    errors.append(validate_password_symbol(form, sanitise_data(field.data)))

    if len(errors) > 0:
        raise ValidationError("\n".join(errors))


# Validate password length
def validate_password_length(form, field):
    if len(field.data) < 8:
        return "Password must be at least 8 characters long."


# Validate password at least 1 uppercase
def validate_password_upper(form, field):
    if not re.search(r"[A-Z]", field.data):
        return "Password must contain at least 1 uppercase letter."


# Validate password at least 1 lowercase
def validate_password_lower(form, field):
    if not re.search(r"[A-Z]", field.data):
        return "Password must contain at least 1 uppercase letter."


# Validate password at least 1 symbol
def validate_password_symbol(form, field):
    if not re.search(r"\W", field.data):
        return "Password must contain at least 1 symbol."


# Validate phone number
def validate_phone_number(form, field):
    if not sanitise_data(field.data).isdigit() or not (10 <= len(sanitise_data(field.data)) <= 15):
        raise ValidationError("Phone number must only contain numbers and be between 10 and 15 digits long.")


# Validate postal code
def validate_postal_code(form, field):
    if not field.data.isdigit() or not (3 <= len(field.data) <= 10):
        raise ValidationError("Postal code must only contain numbers and be between 3 and 10 digits long.")
