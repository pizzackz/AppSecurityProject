import logging
import hashlib
import os
import googleapiclient.discovery

from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Union, Dict, Optional

from flask import Blueprint, request, session, redirect, render_template, flash, url_for, make_response
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt, get_jwt_identity, jwt_required
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash
from google_auth_oauthlib.flow import Flow

from app import db, login_manager
from app.config.config import Config
from app.models import User, Member, Admin, LockedAccount
from app.forms.auth_forms import LoginForm, OtpForm, ConfirmNewMemberForm, ConfirmGoogleLinkForm
from app.utils import clean_input, clear_unwanted_session_keys, generate_otp, send_email, check_auth_stage, check_jwt_values


login_auth_bp: Blueprint = Blueprint("login_auth_bp", __name__, url_prefix="/login")
logger: Logger = logging.getLogger('tastefully')

# Initialise variables
TEMPLATE_FOLDER = "authentication/login"
# Disable the security check for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Convert credentials from Credential object to dictionary
def credentials_to_dict(credentials) -> Dict:
    """Helper function to convert OAuth credentials to a dictionary."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


# Retrieve Google user info using OAtuh credentials
def get_google_user_info(credentials):
    """Helper function to get Google user info using the OAuth credentials."""
    user_info_service = googleapiclient.discovery.build(
        serviceName='oauth2', version='v2',
        credentials=credentials
    )
    # Fetch the user info from Google's API
    user_info = user_info_service.userinfo().get().execute()
    return user_info


# User loader function to retrieve user object from database
@login_manager.user_loader
def load_user(user_id: int) -> Union[User, Member, Admin]:
    user_id = int(user_id)
    user: User = User.query.get(user_id)

    if user:
        if user.type == "member":
            return Member.query.get(user_id)
        elif user.type == "admin":
            return Admin.query.get(user_id)
    return user


# Successful Google Sign-in aftermath case handlers
# Display case based messages
def display_case_messages(flash_message: str, log_message: str):
    flash(flash_message, "error")
    logger.error(log_message)
    return redirect(url_for('login_auth_bp.login'))


# Handle ideal case 1: No account exists with the same email, username, and Google ID
def handle_ideal_case1(email: str, username: str, google_id: str, profile_picture: str):
    # Store important info from google into jwt
    identity = {'email': email, 'username': username, 'google_id': google_id}
    claims = {'profile_picture': profile_picture}
    token = create_access_token(identity=identity, additional_claims=claims)
    response = make_response(redirect(url_for('login_auth_bp.confirm_new_member_account')))
    set_access_cookies(response, token)
    
    # Display messages
    flash("Please confirm if you want to create a new member account.", "info")
    logger.info("Redirecting to confirm new member account creation.")

    return response


# Handle ideal case 2: Existing account with matching google id for user_by_email & user_by_username
def handle_ideal_case2(user_by_email: User, username: str, email: str, profile_picture: str):
    # Get correct endpoint based on user type
    endpoint = "home_bp.home"

    # Update to use google provided profile picture
    try:
        user_by_email.profile_images.source = "google"
        user_by_email.profile_images.google_url = profile_picture
        user_by_email.profile_images.filename = "default.png"
        db.session.commit()
    except Exception as e:
        flash(f"An error occurred while trying to log you in through Google. Please try again later.", "error")
        logger.error(f"Error updating profile_images for user '{username}': {e}")
        return redirect(url_for('login_auth_bp.login'))

    # Clear any jwt & session data
    session.clear()
    response = make_response(redirect(url_for(endpoint)))
    unset_jwt_cookies(response)

    # Log user in and necessary login_details updates
    login_details = user_by_email.login_details
    login_details.update_login()
    login_user(user_by_email)

    # Display messages
    flash(f"Welcome {username}. You are now logged in!", "success")
    logger.info(f"User '{username}' with email '{email}' logged in successfully through Google Sign-in.")

    return response


# Main function to handle all ideal cases
def handle_ideal_cases(user_by_email: Optional[User], user_by_username: Optional[User], user_by_google_id: Optional[User], email: str, username: str, google_id: str, profile_picture: str):
    # Ideal Case 1: No account exists with the same email, username, and Google ID
    if not user_by_email and not user_by_username and not user_by_google_id:
        return handle_ideal_case1(email, username, google_id, profile_picture)

    # Ideal Case 2: Existing account matches both email and Google ID
    if user_by_email and user_by_google_id and user_by_email.google_id == google_id:
        return handle_ideal_case2(user_by_email, username, email, profile_picture)

    return None


# Defective case 1: Email & username exists on same account but no google id associated
def handle_defective_case1(email, username, google_id, profile_picture, type: str):
    if type == "1":
        log_message = f"Email {email} exists but no Google ID is associated. User prompted to link Google account."
    elif type == "2":
        log_message = f"Username {username} exists but no Google ID is associated. User prompted to link Google account."
    
    # Store google data in jwt for fther logic
    identity = {'email': email, 'username': username, 'google_id': google_id}
    claims = {'profile_picture': profile_picture}
    token = create_access_token(identity=identity, additional_claims=claims)
    response = make_response(redirect(url_for('login_auth_bp.link_google')))
    set_access_cookies(response, token)

    # Display messages
    flash("Account exists but is not linked to your Google account. Would you like to link to your Google account?", "info")
    logger.info(log_message)

    return response


# Main function to handle all defective cases
def handle_defective_cases(user_by_email: Optional[User], user_by_username: Optional[User], user_by_google_id: Optional[User], email: str, username: str, google_id: str, profile_picture: str):
    # Defective case 1: Email & username exists on same account but no google id associated
    if (user_by_email and not user_by_email.google_id) or (user_by_username and not user_by_username.google_id):
        if user_by_email and not user_by_email.google_id:
            return handle_defective_case1(email, username, google_id, profile_picture, "1")
        elif user_by_username and not user_by_username.google_id:
            return handle_defective_case1(email, username, google_id, profile_picture, "2")

    # Defective case 2: Google id exists but neither email or username matches
    if user_by_google_id and (user_by_google_id.email != email or user_by_google_id.username != username):
        flash_message = "This Google account is associated with different credentials. Please use the correct credentials."
        log_message = f"Google ID {google_id} is associated with email {user_by_google_id.email} and username {user_by_google_id.username}, but attempted email was {email} and username was {username}."
        display_case_messages(flash_message, log_message)        
    
    # Defective case 3: Partial information mismatch (email/ username/ google id)
    if (user_by_email and user_by_email.google_id != google_id) or (user_by_username and user_by_username.google_id != google_id):
        flash_message = "Partial information mismatch. Please check your credentials."
        log_message = f"Partial information mismatch: Google ID {google_id} with email {email} and username {username}."
        return display_case_messages(flash_message, log_message)

    # Defective case 4: No match for email, username or google id but partial overlap in account information
    if (user_by_email and not user_by_google_id) or (user_by_username and not user_by_google_id):
        flash_message = "Partial overlap in account information. Please check your credentials."
        log_message = f"Partial overlap in account information for email {email} and username {username}."
        return display_case_messages(flash_message, log_message)
    
    return None


# Initial login route
@login_auth_bp.route("/", methods=['GET', 'POST'])
def login():
    """
    Login route to initiate the login process.
    It validates the login form, cleans inputs and stores intermediate stage in session.
    """
    # Clear session keys that are not needed
    clear_unwanted_session_keys()

    form = LoginForm()

    if request.method == "POST" and form.validate_on_submit():
        # Retrieve & clean inputs
        username = clean_input(form.username.data)
        password = form.password.data

        # Check if account exists
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Invalid username or password. Please try again.", "error")
            logger.warning(f"Login attempt with non-existent username: {username}")
            return redirect(url_for("login_auth_bp.login"))

        # Check if account is locked and retrieve the lock reason
        if user.account_status.is_locked:
            locked_account = LockedAccount.query.filter_by(id=user.id).first()
            
            # Check if lock request has been sent
            if locked_account.unlock_request:
                flash("Your account is currently locked. A request to unlock your account has been sent to support. Please wait for further instructions.", "info")
                logger.info(f"Attempt to login to locked account with username '{username}' after request for unlock has been sent.")
                return redirect(url_for('login_auth_bp.login'))

            lock_reason = locked_account.locked_reason if locked_account else "Unknown reason"
            flash(f"Your account has been locked due to the following reason: {lock_reason}. Please contact support below.", "error")
            logger.warning(f"Login attempt for locked account with username '{username}'. Lock reason: {lock_reason}")
            return redirect(url_for("login_auth_bp.login"))

        # Check input password not match stored password
        if not check_password_hash(user.password_hash, password):
            user.account_status.increment_failed_logins()  # Track failed login attempts
            logger.warning(f"Incorrect password attempt for username: {username}")

            # Check if account should be locked (attempts >= 7)
            if user.account_status.failed_login_attempts >= 2:
                User.lock_account(user.id, locked_reason="Too many failed login attempts")
                flash("Your account has been locked due to repeated failed login attemps. Please contact support below.", "error")
                logger.warning(f"Account locked due to failed login attempts for username: {username}.")
                return redirect(url_for("login_auth_bp.login"))

            flash("Invalid username or password. Please try again.", "error")
            return redirect(url_for("login_auth_bp.login"))

        # Create JWT token for sensitive data
        response = redirect(url_for('login_auth_bp.send_otp'))
        identity = {'username': user.username, 'email': user.email}
        token = create_access_token(identity=identity)
        set_access_cookies(response, token)

        # Reset failed login attempts
        user.account_status.reset_failed_logins()

        # Store intermediate stage in session
        session['login_stage'] = 'send_otp'

        # Redirect to send_otp
        return response

    # Render the base login template
    return render_template(f"{TEMPLATE_FOLDER}/login.html", form=form)


# Send otp route
@login_auth_bp.route("/send_otp", methods=['GET'])
@jwt_required()
def send_otp():
    # Check if the session is expired
    if 'login_stage' not in session:
        flash("Your session has expired. Please restart the login process.", "error")
        logger.error(f"Session expired")
        return redirect(url_for('login_auth_bp.login'))

    # Check whether auth stage correct (login_stage == send_otp or verify_email)
    check = check_auth_stage(
        auth_process="login_stage",
        allowed_stages=['send_otp', 'verify_email'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process.",
        log_message="Invalid login stage"
    )
    if check:
        return check

    # Check jwt identity has username, email
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=None,
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process."
    )
    if check_jwt:
        return check_jwt

    # Generate otp
    identity = get_jwt_identity()
    otp = generate_otp()
    hashed_otp = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    otp_expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()  # OTP valid for 10 minutes
    otp_data = {'otp': hashed_otp, 'expiry': otp_expiry}

    # Update JWT token with OTP and expiry
    new_token = create_access_token(identity=identity, additional_claims={"otp_data": otp_data})
    response = redirect(url_for('login_auth_bp.verify_email'))
    set_access_cookies(response, new_token)

    # Try sending email using utility send_email function
    email_body = f"Your OTP is {otp}. It will expire in 10 minutes."
    login_stage = session.get("login_stage")
    if send_email(identity['email'], "Your OTP Code", email_body):
        flash_msg = "OTP has been sent to your email address."
        log_msg = f"OTP sent to {identity['email']}"

        if login_stage == 'send_otp':
            session["login_stage"] = "verify_email"
        elif request.args.get("expired_otp") == "True" and login_stage == "verify_email":
            flash_msg = "Your OTP has expired. A new OTP has been sent to your email address."
            log_msg = f"OTP expired and re-sent to {identity['email']}"
        elif login_stage == 'verify_email':
            flash_msg = "OTP has been re-sent to your email address."
            log_msg = f"OTP re-sent to {identity['email']}"

        flash(flash_msg, 'info')
        logger.info(log_msg)
    else:
        if login_stage == "send_otp":
            session.clear()
            response = redirect(url_for("login_auth_bp.login"))
            unset_jwt_cookies(response)
        flash("An error occurred while sending the OTP. Please try again.", "error")
        logger.error(f"Failed to send OTP to {identity['email']}")

    # Redirect to verify email
    return response


# Verify email route
@login_auth_bp.route("/verify_email", methods=["GET", "POST"])
@jwt_required()
def verify_email():
    # Redirect to signup & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        session.clear()
        response = redirect(url_for('login_auth_bp.login'))
        unset_jwt_cookies(response)
        flash("Login process restarted.", "info")
        logger.info("User opted to restart the login process.")
        return response

    # Check session not expired & signup_stage == verify_email
    check = check_auth_stage(
        auth_process="login_stage",
        allowed_stages=['verify_email'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process.",
        log_message="Invalid login stage"
    )
    if check:
        return check

    # Check jwt identity has username, email & jwt claims has otp_data
    check_jwt = check_jwt_values(
        required_identity_keys=['username', 'email'],
        required_claims=['otp_data'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Your session has expired. Please restart the login process."
    )
    if check_jwt:
        return check_jwt

    # Check whether otp_data expired
    jwt = get_jwt()
    identity = get_jwt_identity()
    otp_data = jwt.get('otp_data')
    otp_expiry = datetime.fromisoformat(otp_data['expiry'])
    if otp_expiry < datetime.now(timezone.utc):
        return redirect(url_for('login_auth_bp.send_otp', expired_otp=True))
    
    # Check if the uer account exists
    identity = get_jwt_identity()
    user = User.query.filter_by(username=identity['username'], email=identity['email']).first()
    if not user:
        flash("An error occurred. Please restart the login process.", "error")
        logger.error(f"User account not found for email: {identity['email']}")
        return redirect(url_for('login_auth_bp.login'))

    form = OtpForm()
    if request.method == "POST" and form.validate_on_submit():
        # Retrieve user provided input, sanitize & hash it
        user_otp = clean_input(form.otp.data)
        hashed_user_otp = hashlib.sha256(user_otp.encode("utf-8")).hexdigest()

        # Check whether hashed input otp == actual otp stored in jwt
        if not hashed_user_otp == otp_data['otp']:
            flash("Invalid OTP. Please try again.", "error")
            logger.warning(f"Invalid OTP attempt for user: {identity['username']}")
            return redirect(url_for("login_auth_bp.verify_email"))

        # Get correct endpoint based on user type
        user = User.query.filter_by(username=identity['username'], email=identity['email']).first()
        endpoint = "home_bp.home"

        # Clear any jwt & session data
        session.clear()
        response = redirect(url_for(endpoint))
        unset_jwt_cookies(response)

        # Log user in and necessary database updates
        login_details = user.login_details
        login_details.update_login()
        login_user(user)

        # Display messages
        flash("Email verified successfully. You are now logged in.", "success")
        logger.info(f"Email verified for user - '{identity['username']}' and user is logged in")

        return response

    # Render the verify email template
    return render_template(f'{TEMPLATE_FOLDER}/verify_email.html', form=form)


# Google login route
@login_auth_bp.route("/google_login", methods=['GET'])
def google_login():
    # Create OAuth 2.0 flow object
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": Config.GOOGLE_CLIENT_ID,
                "client_secret": Config.GOOGLE_CLIENT_SECRET,
                "auth_uri": Config.GOOGLE_AUTH_URI,
                "token_uri": Config.GOOGLE_TOKEN_URI,
                "redirect_uris": Config.GOOGLE_REDIRECT_URIS
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        redirect_uri=url_for('login_auth_bp.google_callback', _external=True)
    )

    # Generate authorisation url & state token
    authorisation_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='select_account')

    # Store google oauth state token in session
    session['google_outh_state'] = state

    # Redirect to Google's OAuth 2.0 server
    return redirect(authorisation_url)


# Route to handle Google callback
@login_auth_bp.route("/google_callback", methods=['GET'])
def google_callback():
    # Handle Google Sign-in cancel request
    if 'error' in request.args:
        error = request.args['error']
        if error == 'access_denied':
            flash("Google login was canceled.", "info")
            logger.info("Google login was canceled by the user.")
            return redirect(url_for('login_auth_bp.login'))

    # Retrieve state token from session
    state = session.get('google_oauth_state')

    # Create new OAuth 2.0 flow object using state token
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": Config.GOOGLE_CLIENT_ID,
                "client_secret": Config.GOOGLE_CLIENT_SECRET,
                "auth_uri": Config.GOOGLE_AUTH_URI,
                "token_uri": Config.GOOGLE_TOKEN_URI,
                "redirect_uris": Config.GOOGLE_REDIRECT_URIS
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        state=state,
        redirect_uri=url_for('login_auth_bp.google_callback', _external=True)  # Set the redirect URI for the OAuth flow
    )

    # Exchange authorisation code for access token
    authorisation_response = request.url
    flow.fetch_token(authorization_response=authorisation_response)

    # Get credentials object & data in object
    credentials = flow.credentials
    google_user_info = get_google_user_info(credentials)
    email = google_user_info['email']
    username = google_user_info['name']
    google_id = google_user_info['id']
    profile_picture = google_user_info.get('picture', None)

    # Check if the user exists using email, username and Google ID
    user_by_email = User.query.filter_by(email=email).first()
    user_by_username = User.query.filter_by(username=username).first()
    user_by_google_id = User.query.filter_by(google_id=google_id).first()

    # Handle 4 possible defective cases
    defective_case_response = handle_defective_cases(user_by_email, user_by_username, user_by_google_id, email, username, google_id, profile_picture)
    if defective_case_response:
        return defective_case_response

    # Handle 2 ideal cases
    ideal_case_response = handle_ideal_cases(user_by_email, user_by_username, user_by_google_id, email, username, google_id, profile_picture)
    if ideal_case_response:
        return ideal_case_response

    flash("An unexpected error occurred. Please try again.", "error")
    logger.error("Unidentified error after successful Google Sign-in")

    return redirect(url_for("login_auth_bp.login"))


# Create new account route - Using google credentials
@login_auth_bp.route("/confirm_new_member_account", methods=['GET', 'POST'])
@jwt_required()
def confirm_new_member_account():
    # Check for correct JWT identity keys and claims
    check = check_jwt_values(
        required_identity_keys=['email', 'username', 'google_id'],
        required_claims=['profile_picture'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Invalid session. Please try again.",
        log_message="Invalid JWT identity or claims during new member account confirmation."
    )
    if check:
        return check
    
    identity = get_jwt_identity()
    claims = get_jwt()
    form = ConfirmNewMemberForm()

    if request.method == 'POST' and form.validate_on_submit():
        # User chose not to create an account
        if form.confirm.data == 'no':
            session.clear()
            response = redirect(url_for('login_auth_bp.login'))
            unset_jwt_cookies(response)

            # Display messages
            flash("Member account creation canceled.", "info")
            logger.info(f"User '{identity['username']}' opted not to create a new member account after successful Google Sign-in.")

        # User chose to create new member account
        elif form.confirm.data == "yes":
            email = identity['email']
            username = identity['username']
            google_id = identity['google_id']
            profile_picture = claims.get('profile_picture', None)

            # Create new user with given email, username, google_id, and profile picture
            new_user = Member.create_by_google(username=username, email=email, google_id=google_id, google_image_url=profile_picture)
            if not new_user:
                session.clear()
                response = redirect(url_for('login_auth_bp.login'))
                unset_jwt_cookies(response)
                flash("An error occurred while creating the account. Please try again.", "error")
                logger.error(f"Failed to create new member account for {email}.")
                return redirect(url_for('login_auth_bp.login'))

            endpoint = "home_bp.home"

            # Clear any jwt & session data
            session.clear()
            response = redirect(url_for(endpoint))
            unset_jwt_cookies(response)

            # Log user in and necessary login_details updates
            login_details = new_user.login_details
            login_details.update_login()
            login_user(new_user)

            # Display messages
            flash("Member account created successfully. You are now logged in.", "success")
            logger.info(f"Created new member account for user '{username}' with email '{email}' after successful Google Sign-in.")
        
        # Case when confirm data is not 'yes' or 'no'
        else:
            session.clear()
            response = redirect(url_for(endpoint))
            unset_jwt_cookies(response)
            login_user(new_user)

            # Display messages
            flash("An unexpected error occurred. Please try again.", "error")
            logger.info(f"User '{username}' with email '{email}' tried an unknown action after successful Google Sign-in.")

        return response

    # Render the confirm new member account creation template
    return render_template(f"{TEMPLATE_FOLDER}/new_member_acc.html", form=form)


# Linking Google account route
@login_auth_bp.route("/link_google", methods=['GET', 'POST'])
@jwt_required()
def link_google():
    # Check for correct JWT identity keys
    check = check_jwt_values(
        required_identity_keys=['email', 'username', 'google_id'],
        required_claims=['profile_picture'],
        fallback_endpoint='login_auth_bp.login',
        flash_message="Invalid session. Please try again.",
        log_message="Invalid JWT identity or claims during Google account linking."
    )
    if check:
        return check
    
    identity = get_jwt_identity()
    claims = get_jwt()
    form = ConfirmGoogleLinkForm()

    if request.method == 'POST' and form.validate_on_submit():
        # User chose not to link the Google account
        if form.confirm.data == 'no':
            session.clear()
            response = redirect(url_for('login_auth_bp.login'))
            unset_jwt_cookies(response)
            flash("Google account linking canceled.", "info")
            logger.info(f"User '{identity['username']}' opted not to link the Google account.")
            return response

        # User chose to link Google account
        if form.confirm.data == "yes":
            email = identity['email']
            username = identity['username']
            google_id = identity['google_id']
            profile_picture = claims.get('profile_picture', None)

            user = User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first()
            if user:
                # Update user in database
                if not user.username or user.username != username:
                    user.username = username
                if not user.email or user.email != email:
                    user.email = email
                user.google_id = google_id
                if profile_picture:
                    user.profile_images.source = "google"
                    user.profile_images.google_url = profile_picture
                db.session.commit()

                # Get correct endpoint based on user type
                endpoint = "home_bp.home"

                # Clear any jwt & session data
                session.clear()
                response = redirect(url_for(endpoint))
                unset_jwt_cookies(response)

                # Log user in and necessary login_details updates
                login_details = user.login_details
                login_details.update_login()
                login_user(user)

                # Display messages
                flash("Google account linked successfully. You are now logged in.", "success")
                logger.info(f"User '{username}' with email '{email}' logged in after linking to Google Account.")

                return response

            # User not found
            session.clear()
            response = redirect(url_for('login_auth_bp.login'))
            unset_jwt_cookies(response)
            
            flash("An error occurred while linking the Google account. Please try again.", "error")
            logger.error(f"Failed to link Google account for {email}.")
            return response

    # Render the confirm Google account linking template
    return render_template(f"{TEMPLATE_FOLDER}/confirm_google_link.html", form=form)
