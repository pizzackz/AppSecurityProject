import os
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from dotenv import load_dotenv


# Get email configurations
load_dotenv()

GMAIL_USER: Optional[str] = os.getenv("GMAIL_USER")
GMAIL_PASSWORD: Optional[str] = os.getenv("GMAIL_PASSWORD")


def generate_otp(length: int = 6) -> str:
    """Generate a one-time password (OTP) with a specified length.
    
    Args:
        length (int): The length of the OTP to generate. Default is 6.

    Returns:
        str: The generated OTP.
    """
    return ''.join(random.choices(string.digits, k=length))


def send_email(to_email: str, subject: str, body: str) -> Optional[bool]:
    """
    Send an email securely using Gmail's SMTP server.

    Args:
        to_email (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The body of the email.
    
    Raises:
        Exception: If there is an issue sending the email.
    """
    msg = MIMEMultipart()
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg["subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        # Establish secure session with Gmail's outgoing SMTP server using TLS
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Start TLS for security
        server.login(GMAIL_USER, GMAIL_PASSWORD)  # Login with credentials

        # Send email
        text = msg.as_string()
        server.sendmail(GMAIL_USER, to_email, text)

        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
    finally:
        server.quit()  # Terminate SMTP session


def send_otp_email(to_email: str, otp: str) -> Optional[bool]:
    """
    Send an OTP email to the specified email address.

    Args:
        to_email (str): The recipient's email address.
        otp (str): The one-time password to send.
    
    Raises:
        Exception: If there is an issue sending the email.
    """
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp}"
    return send_email(to_email, subject, body)
