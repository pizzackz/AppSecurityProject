import re
import io
import bleach
import imghdr
from wtforms import ValidationError
from werkzeug.utils import secure_filename
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
    return bleach.clean(data)


# Validator for unique username
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
    otp = sanitise_data(field.data)
    if not otp.isdigit() or len(otp) != 6:
        raise ValidationError("OTP must be a 6-digit number.")


# Validator for password complexity policy
def validate_password_complexity(form, field):
    """Validate the password complexity.

    Args:
        form: The form instance.
        field: The field instance containing the data to validate.

    Raises:
        ValidationError: If the password does not meet complexity requirements.
    """
    errors = list()
    data = sanitise_data(field.data)

    if not validate_password_length(data):
        errors.append("Password must be at least 8 characters long.")
    if not validate_password_upper(data):
        errors.append("Password must contain at least 1 uppercase letter.")
    if not validate_password_lower(data):
        errors.append("Password must contain at least 1 lowercase letter.")
    if not validate_password_number(data):
        errors.append("Password must contain at least 1 number.")
    if not validate_password_symbol(data):
        errors.append("Password must contain at least 1 symbol.")

    if errors:
        raise ValidationError("\n".join(errors))


# Validate password length
def validate_password_length(password: str) -> bool:
    """Validate the password length.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the validation passes, False otherwise.
    """
    return len(password) >= 8


# Validate password at least 1 uppercase
def validate_password_upper(password: str) -> bool:
    """Validate that the password contains at least one uppercase letter.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the validation passes, False otherwise.
    """
    return bool(re.search(r"[A-Z]", password))


# Validate password at least 1 lowercase
def validate_password_lower(password: str) -> bool:
    """Validate that the password contains at least one lowercase letter.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the validation passes, False otherwise.
    """
    return bool(re.search(r"[a-z]", password))


# Validate password at least 1 number
def validate_password_number(password: str) -> bool:
    """Validate that the password contains at least one number.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the validation passes, False otherwise.
    """
    return bool(re.search(r"\d", password))


# Validate password at least 1 symbol
def validate_password_symbol(password: str) -> bool:
    """Validate that the password contains at least one symbol.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the validation passes, False otherwise.
    """
    return bool(re.search(r"\W", password))


# Validate phone number
def validate_phone_number(form, field):
    """
    Validate the phone number format.

    Args:
        form: The form instance.
        field: The field instance containing the phone number.

    Raises:
        ValidationError: If the phone number is not valid.
    """
    phone_number = field.data.strip()
    pattern = r"^\+?\d[\d -]{7,14}\d$"
    if not re.match(pattern, phone_number):
        raise ValidationError("Invalid phone number format. Include country code if applicable, and use digits, spaces, or dashes only.")


# Validate postal code
def validate_postal_code(form, field):
    """
    Validate the postal code format.

    Args:
        form: The form instance.
        field: The field instance containing the postal code.

    Raises:
        ValidationError: If the postal code is not valid.
    """
    postal_code = field.data.strip()
    if not postal_code.isdigit() or len(postal_code) not in {5, 6}:
        raise ValidationError("Invalid postal code format. Enter a 5 or 6-digit number.")


# Validators for postal code
def six_digit_postal_code_validator(form, field):
    if len(field.data) != 6:
        raise ValidationError("Please enter a valid 6-digit postal code.")
    if field.data == "000000":
        raise ValidationError("Please enter a valid 6-digit postal code.")
    try:
        field.data = int(field.data)
    except ValueError:
        raise ValidationError("Please enter a valid 6-digit postal code.")


# Validators for phone number
def phone_number_validator(form, field):
    pattern = r"^(8|9)\d{3} \d{4}$"
    field_data_str = str(field.data)  # Ensure data is a string
    if not re.match(pattern, field_data_str):
        raise ValidationError("Please enter a valid phone number in the format 8/9XXX XXXX.")


