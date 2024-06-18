import re
import bleach
from wtforms import ValidationError
from app.models import User
from email_validator import validate_email, EmailNotValidError


# Function to sanitise data first before validating
def sanitise_data(data: str) -> str:
    """Sanitise input data using bleach.

    Args:
        data (str): The input data to sanitise.

    Returns:
        str: The sanitised data.
    """
    sanitised_data = bleach.clean(data)
    return sanitised_data


# Validtor for unique username
def unique_username(form, field):
    """Validate that the username is unique.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the username is already in use.
    """
    if User.query.filter_by(username=sanitise_data(field.data)).first():
        raise ValidationError("Username is already in use. Please choose another one.")
    

# Validator for unique email
def unique_email(form, field):
    """Validate that the email is unique.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the email is already in use.
    """
    if User.query.filter_by(email=sanitise_data(field.data)).first():
        raise ValidationError("Email is already in use. Please choose another one.")


# Validator for email format
def validate_email_format(form, field):
    """Validate the email format.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the email format is invalid.
    """
    try:
        validate_email(field.data)
    except EmailNotValidError as e:
        raise ValidationError(str(e))


# Validator for OTP length
def validate_otp(form, field):
    """Validate the OTP.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the OTP is not a 6-digit number.
    """
    if not sanitise_data(field.data).isdigit() or len(sanitise_data(field.data)) != 6:
        raise ValidationError("OTP must be a 6 digit number.")


# Validators for password complextiy policy
def validate_password_complexity(form, field):
    """Validate the password complexity.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the password does not meet complexity requirements.
    """
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
    """Validate the password length.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Returns:
        str: Error message if the validation fails.
    """
    if len(field.data) < 8:
        return "Password must be at least 8 characters long."


# Validate password at least 1 uppercase
def validate_password_upper(form, field):
    """Validate that the password contains at least one uppercase letter.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Returns:
        str: Error message if the validation fails.
    """
    if not re.search(r"[A-Z]", field.data):
        return "Password must contain at least 1 uppercase letter."


# Validate password at least 1 lowercase
def validate_password_lower(form, field):
    """Validate that the password contains at least one lowercase letter.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Returns:
        str: Error message if the validation fails.
    """
    if not re.search(r"[A-Z]", field.data):
        return "Password must contain at least 1 uppercase letter."


# Validate password at least 1 symbol
def validate_password_symbol(form, field):
    """Validate that the password contains at least one symbol.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Returns:
        str: Error message if the validation fails.
    """
    if not re.search(r"\W", field.data):
        return "Password must contain at least 1 symbol."


# Validate phone number
def validate_phone_number(form, field):
    """Validate the phone number.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the phone number is invalid.
    """
    if not sanitise_data(field.data).isdigit() or not (10 <= len(sanitise_data(field.data)) <= 15):
        raise ValidationError("Phone number must only contain numbers and be between 10 and 15 digits long.")


# Validate postal code
def validate_postal_code(form, field):
    """Validate the postal code.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the postal code is invalid.
    """
    if not field.data.isdigit() or not (3 <= len(field.data) <= 10):
        raise ValidationError("Postal code must only contain numbers and be between 3 and 10 digits long.")
