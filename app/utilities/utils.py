import hashlib
import secrets
import string
import bleach
import logging

from datetime import datetime, timedelta, timezone
from logging import Logger
from flask import current_app, session, redirect, url_for, flash
from flask_mail import Message
from typing import List


# Use logger configured in '__init__.py'
logger: Logger = logging.getLogger('tastefully')


# OTP data class
class OTPData:
    def __init__(self, otp: str, expiration_minutes: int = 5):
        self.otp = otp
        self.hashed_otp = self.hash_otp(otp)
        self.expiration_time = datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)

    @staticmethod
    def hash_otp(otp: str) -> str:
        """Hash the OTP using SHA-256."""
        return hashlib.sha256(otp.encode()).hexdigest()

    def is_expired(self) -> bool:
        """Check if the OTP is expired."""
        return datetime.now(timezone.utc) > self.expiration_time

    def to_dict(self) -> dict:
        """Convert OTPData to a dictionary for session storage."""
        return {
            'hashed_otp': self.hashed_otp,
            'expiration_time': self.expiration_time.isoformat()
        }

    @classmethod
    def from_dict(cls, data: dict):
        """Create an OTPData object from a dictionary."""
        obj = cls.__new__(cls)
        obj.hashed_otp = data['hashed_otp']
        obj.expiration_time = datetime.fromisoformat(data['expiration_time'])
        return obj


# Authentication data class
class AuthData:
    def __init__(self, email, auth_stage, next_step, fallback_step, default_step, username=None):
        self.username = username
        self.email = email
        self.auth_stage = auth_stage
        self.next_step = next_step
        self.fallback_step = fallback_step
        self.default_step = default_step

    def to_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'auth_stage': self.auth_stage,
            'next_step': self.next_step,
            'fallback_step': self.fallback_step,
            'default_step': self.default_step
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            username=data.get('username'),
            email=data['email'],
            auth_stage=data['auth_stage'],
            next_step=data['next_step'],
            fallback_step=data['fallback_step'],
            default_step=data['default_step']
        )


# Functions
# Clean input function
def clean_input(data: str, strip: bool = True) -> str:
    """Sanitise and strip input data using bleach."""
    if not strip: return bleach.clean(data)

    return bleach.clean(data.strip())


# Generate OTP function
def generate_otp(length: int = 6) -> str:
    """Generate a secure OTP using a cryptographically secure random number generator."""
    characters = string.digits
    otp = ''.join(secrets.choice(characters) for _ in range(length))
    return otp


# Hash otp
def hash_otp(otp):
    """Hash the OTP using SHA-256."""
    return hashlib.sha256(otp.encode()).hexdigest()


# General send email function
def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send an email using Flask-Mail."""
    from app import mail

    msg = Message(subject, sender=current_app.config['MAIL_USERNAME'], recipients=[to_email])
    msg.body = body

    try:
        mail.send(msg)
        logger.info(f'Email sent to {to_email} with subject "{subject}"')
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email} with subject '{subject}': {e}")
        return False
