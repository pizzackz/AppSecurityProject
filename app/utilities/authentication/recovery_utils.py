import logging

from logging import Logger
from typing import Optional
from flask import flash

from app import User


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# Get user object from db by email
def get_user_by_email(email: str) -> Optional[User]:
    """Retrieve a user by email."""
    user = User.query.filter_by(email=email).first()
    if not user:
        raise ValueError(f"No account found for email '{email}'.")
    return user


# Validate recovery options
def validate_recovery_option(option: str) -> None:
    """Validate the recovery option selected by the user."""
    valid_options = ("recover_username", "change_password")
    if option not in valid_options:
        raise ValueError(f"Selected action '{option}' is invalid.")


# Handle recovery option
def handle_recovery_option(option: str, email: str) -> None:
    """Handle the selected recovery option and display appropriate messages."""
    validate_recovery_option(option)

    if option == "recover_username":
        logger.info(f"User with email '{email}' chose to recover username.")
        return None
    elif option == "change_password":
        logger.info(f"User with email '{email}' chose to change password.")
        return None

    raise ValueError(f"Invalid option '{option}' selected.")
