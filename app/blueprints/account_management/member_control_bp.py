import logging

from logging import Logger
from typing import Optional

from flask import Blueprint, Response, request, session, redirect, render_template, flash, url_for, make_response
from flask_jwt_extended import unset_jwt_cookies
from flask_login import login_required, current_user

from app.models import Member, LockedAccount, PasswordResetToken
from app.forms.forms import LockDeleteMemberForm
from app.utils import clean_input, send_email, check_admin, check_session_keys, clear_unwanted_session_keys, get_image_url


# Initialise variables
member_control_bp = Blueprint("member_control_bp", __name__, url_prefix="/admin/members")
logger: Logger = logging.getLogger('tastefully')

TEMPLATE_FOLDER = "account_management/member"
ESSENTIAL_KEYS = {'_user_id', '_fresh', '_id'}
MEMBER_SPECIFIC_ESSENTIAL_KEYS = {'_user_id', '_fresh', '_id', "member_id"}


# Check admin key function
def check_admin_key(value: str, current_user, fallback_endpoint: str) -> Optional[Response]:
    # Check if admin key has exactly length of 64 characters
    if len(value) != 64:
        flash("Invalid admin key!", "error")
        logger.warning(f"Admin '{current_user.username}' tried to enter a fake admin key with length of '{len(value)}' characters.")
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        return response

    # Check if admin key corresponds to the one stored
    if value != current_user.admin_key:
        flash("Invalid admin key!", "error")
        logger.warning(f"Admin '{current_user.username}' tried to enter an admin key that doesn't belong to the admin or is fake.")
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        return response

    # Check if admin key is outdated/ expired
    if current_user.admin_key_expires_at <= datetime.now():
        flash("Your admin key has expired! Contact support to get a new one.", "error")
        logger.warning(f"Admin '{current_user.username}' tried to lock a member account using an expired admin key.")
        response = make_response(redirect(url_for(fallback_endpoint)))
        unset_jwt_cookies(response)
        return response
    
    return None


# View members route
@member_control_bp.route("/", methods=['GET', 'POST'])
@login_required
def view_members():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Redirect to member details when clicked on any entry provided there is an member id
    if request.method == "POST":
        # Check whether have member id in form
        member_id = request.form.get("member_id")
        if not member_id:
            flash("Failed to select member. Please try again.", "error")
            logger.warning("Failed to retrieve member ID when trying to view specific member account details.")
            return redirect(url_for("member_control_bp.view_members"))

        session['member_id'] = member_id
        logger.info(f"Member '{member_id}' selected for viewing details.")
        return redirect(url_for("member_control_bp.view_member_details"))

    # Fetch all member accounts
    members = Member.query.all()

    # Define which attributes to display in member list view
    member_list_data = [{
        "image": get_image_url(member),
        "id": member.id,
        "username": member.username,
        "email": member.email,
        "subscription_plan": member.subscription_plan.capitalize(),
        "created_at": member.created_at,
        "last_login": member.login_details.last_login if member.login_details else None,
        "account_locked": member.account_status.is_locked if member.account_status else False,
        "unlock_request": (
            LockedAccount.query.filter_by(id=member.id).first().unlock_request
            if member.account_status.is_locked and LockedAccount.query.filter_by(id=member.id).first()
            else False
        ),
        "is_online": member.login_details.is_active
    } for member in members]

    # Render the view members template with fetched data
    return render_template(f"{TEMPLATE_FOLDER}/view_members.html", member_data=member_list_data, count=len(member_list_data))


# Specific member account view route
@member_control_bp.route("/view", methods=['GET', 'POST'])
@login_required
def view_member_details():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session

    # Check whether member account exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(ESSENTIAL_KEYS)
        flash("Member account not found.", "error")
        logger.warning(f"Member account with ID '{member_id}' not found.")
        return redirect(url_for("member_control_bp.view_members"))

    # Properly handle different actions
    action = request.args.get('action') or request.form.get("action")
    if action:
        if action == "back":
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            return redirect(url_for("member_control_bp.view_members"))

        if action == "lock":
            flash("Please provide a reason for locking the member account.", "info")
            logger.info(f"Admin '{current_user.username}' attempting to lock member account '{member.username}'.")
            return redirect(url_for("member_control_bp.lock_member"))

        if action == "unlock":
            logger.info(f"Admin '{current_user.username}' attempting to unlock member account '{member.username}'.")
            return redirect(url_for("member_control_bp.unlock_member"))

        if action == "revoke_plan":
            flash(f"Please provide a reason to revoke the account's subscription plan.")
            logger.info(f"Admin '{current_user.username}' attempting to revoked member account '{member.username}' subscription plan.")
            return redirect(url_for("member_control_bp.revoke_plan"))

        if action == "delete":
            flash(f"Please provide a reason to delete the account.", "info")
            logger.info(f"Admin '{current_user.username}' attempting to delete member account '{member.username}'.")
            return redirect(url_for("member_control_bp.delete_member"))

        if action == "reset_password":
            logger.info(f"Admin '{current_user.username}' attempting to send reset password link to member email '{member.email}'.")
            return redirect(url_for("member_control_bp.send_password_link"))

        if action == "view_order_history":
            return redirect(url_for("member_order_bp.order_history"))

        if action == "view_activities":
            # TODO: Redirect to Jacen's route to display all member activities
            print("Redirecting to view activities")
            return redirect(url_for("member_control_bp.view_member_details"))
        
    # Prepare data for rendering
    member_data = {
        "status": "Online" if member.login_details.is_active else "Offline",
        "locked": member.account_status.is_locked,
        "image": get_image_url(member),
        "id": member.id,
        "username": member.username,
        "email": member.email,
        "phone_number": member.phone_number,
        "address": member.address,
        "postal_code": member.postal_code,
        "subscription_plan": member.subscription_plan.capitalize(),
        "created_at": member.created_at,
        "updated_at": member.updated_at,
        "failed_login_attempts": member.account_status.failed_login_attempts,
        "last_failed_login_attempt": member.account_status.last_failed_login_attempt,
        "last_login": member.login_details.last_login,
        "last_logout": member.login_details.last_logout,
        "login_count": member.login_details.login_count,
        "unlock_request": (
            LockedAccount.query.filter_by(id=member.id).first().unlock_request
            if member.account_status.is_locked and LockedAccount.query.filter_by(id=member.id).first()
            else False
        ),
        "locked_reason": (
            LockedAccount.query.filter_by(id=member.id).first().locked_reason
            if member.account_status.is_locked and LockedAccount.query.filter_by(id=member.id).first()
            else False
        )
    }

    # Render specific member view template with fetched data
    return render_template(f"{TEMPLATE_FOLDER}/view_member_details.html", member=member_data)


# Lock member route
@member_control_bp.route("/view/lock", methods=['GET', 'POST'])
@login_required
def lock_member():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session
    
    # Redirect to view member details & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for('member_control_bp.view_member_details'))
        unset_jwt_cookies(response)
        flash("Member locking process cancelled.", "info")
        logger.info(f"Admin '{current_user.username}' opted to cancel the member locking process.")
        return response
    
    # Check whether member in session
    no_member_id = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_member_details',
        flash_message='There is no member selected to lock. Please choose an member account to lock.',
        log_message='User tried to lock an member account without provided the account id',
        keys_to_keep=MEMBER_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_member_id:
        return no_member_id

    # Check whether account actually exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the member account to lock", "error")
        logger.error(f"Admin '{current_user.username}' tried lock an member without providing the id for an existing account")
        return redirect(url_for("member_control_bp.view_member_details"))
    
    # Check whether account is not locked
    locked_account = LockedAccount.query.get(member_id)
    if locked_account:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Member account is already locked.", "error")
        logger.error(f"Admin '{current_user.username}' tried to lock member account '{member.username}' even though it is already locked.")
        return redirect(url_for("member_control_bp.view_member_details"))

    form = LockDeleteMemberForm()
    if request.method == "POST" and form.validate_on_submit():
        # Sanitise inputs
        reason = clean_input(form.reason.data)
        admin_key = clean_input(form.admin_key.data)

        # Check if admin key is valid
        not_valid_admin_key = check_admin_key(admin_key, current_user, fallback_endpoint="member_control_bp.lock_member")
        if not_valid_admin_key:
            return not_valid_admin_key

        # Try sending email using utility send_email function
        email_body = f"Your account has been locked. The reason is:\n{reason}"
        if send_email(member.email, "Account Locked", email_body):
            if Member.lock_account(id_to_lock=member_id, locked_reason=reason, locker_id=current_user.id):
                clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
                flash("Successfully locked member account!", "success")
                logger.info(f"Admin '{current_user.username}' successfully locked member with member id of '{id}' with reason:\n{reason}")
                return redirect(url_for("member_control_bp.view_member_details"))
            else:
                clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
                flash("An error occurred while locking the account.")
                return redirect(url_for("member_control_bp.view_member_details"))
        else:
            clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
            flash("An error occurred while locking the account.")
            logger.error(f"Failed to send email to inform member '{member.username}' that their account has been locked.")
            return redirect(url_for("member_control_bp.member_details"))

    # Render the lock member template
    return render_template(f"{TEMPLATE_FOLDER}/lock_member.html", form=form)


# Unlock member account
@member_control_bp.route("/view/unlock", methods=['GET'])
@login_required
def unlock_member():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session

    # Check whether account actually exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the member account to lock", "error")
        logger.error(f"Admin '{current_user.username}' tried lock an member without providing the id for an existing account")
        return redirect(url_for("member_control_bp.view_member_details"))
    
    # Check whether account is locked
    locked_account = LockedAccount.query.get(member_id)
    if not locked_account:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Member account is already unlocked.", "error")
        logger.error(f"Admin '{current_user.username}' tried to unlock member account '{member.username}' even though it is not locked.")
        return redirect(url_for("member_control_bp.view_member_details"))

    # Try sending email using utility send_email function
    email_body = "Your account has been unlocked."
    if send_email(member.email, "Account Unlocked", email_body):
        if Member.unlock_account(member_id):
            clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
            flash("Successfully unlocked member account!", "success")
            logger.info(f"Successfully unlocked member with member id of '{id}'.")
            return redirect(url_for("member_control_bp.view_member_details"))
        else:
            clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
            flash("An error occurred while locking the account.")
            return redirect(url_for("member_control_bp.view_member_details"))
    else:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("An error occurred while unlocking the account.")
        logger.error(f"Failed to send email to inform member '{member.username}' that their account has been unlocked.")
        return redirect(url_for("member_control_bp.view_member_details"))


# Revoke subscription plan route
@member_control_bp.route("/view/revoke_plan", methods=['GET', 'POST'])
@login_required
def revoke_plan():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session
    
    # Redirect to view member details & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for('member_control_bp.view_member_details'))
        unset_jwt_cookies(response)
        flash("Member subscription revoking process cancelled.", "info")
        logger.info(f"Admin '{current_user.username}' opted to cancel the member subscription revoking process.")
        return response
    
    # Check whether member in session
    no_member_id = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_member_details',
        flash_message='There is no member selected to lock. Please choose an member account to lock.',
        log_message='User tried to revoke a member\'s subscription without providing the account id.',
        keys_to_keep=MEMBER_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_member_id:
        return no_member_id

    # Check whether account actually exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the member account to revoke the plan for.", "error")
        logger.error(f"Admin '{current_user.username}' tried revoke subscription for member without providing the id for an existing account")
        return redirect(url_for("member_control_bp.view_member_details"))
    
    # Check whether member is actually a premium member
    if member.subscription_plan != "premium":
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Member is currently not a premium member.", "error")
        logger.error(f"Admin '{current_user.username}' tried to revoke subscription plan for member '{member.username}' even though they are not subscribed.")
        return redirect(url_for("member_control_bp.view_member_details"))
    
    form = LockDeleteMemberForm()
    if request.method == "POST" and form.validate_on_submit():
        # Sanitise inputs
        reason = clean_input(form.reason.data)
        admin_key = clean_input(form.admin_key.data)

        # Check valid admin key
        not_valid_admin_key = check_admin_key(admin_key, current_user, fallback_endpoint="member_control_bp.revoke_plan")
        if not_valid_admin_key:
            return not_valid_admin_key
        
        # Revoke the subscription plan
        revoke_plan = member.revoke_plan()
        if not revoke_plan:
            flash("An error occurred while revoking the account subscription.")
            logger.error(f"Couldn't reset subscription plan data for member '{member.username}'.")
            return redirect(url_for("member_control_bp.view_admin_details"))
        
        # Try sending email using utility send_email function
        email_body = f"Your account subscription has been revoked. The reason is:\n{reason}"
        if send_email(member.email, "Subscription revoked", email_body):
            clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
            flash("Successfully revoked member account subscription!", "success")
            logger.info(f"Admin '{current_user.username}' successfully revoked member subscription with member id of '{id}' with reason:\n{reason}")
            return redirect(url_for("member_control_bp.view_member_details"))
        else:
            clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
            flash("An error occurred while revoking the account subscription.")
            logger.error(f"Failed to send email to inform member '{member.username}' that their account subscription has been revoked.")
            return redirect(url_for("member_control_bp.member_details"))
    
    # Render the subscription revoking template
    return render_template(f"{TEMPLATE_FOLDER}/revoke_plan.html", form=form)


# Delete member route
@member_control_bp.route("/view/delete", methods=['GET', 'POST'])
@login_required
def delete_member():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session
    
    # Redirect to view member details & clear temp data in session & jwt when pressed 'back'
    if 'action' in request.args and request.args.get('action') == 'back':
        # Clear session and JWT data
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for('member_control_bp.view_member_details'))
        unset_jwt_cookies(response)
        flash("Member deletion cancelled.", "info")
        logger.info(f"Admin '{current_user.username}' opted to cancel the member deletion process.")
        return response
    
    # Check whether member in session
    no_member_id = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_member_details',
        flash_message='There is no member selected to delete. Please choose an member account to delete.',
        log_message='User tried to delete a member account without providing the account id.',
        keys_to_keep=MEMBER_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_member_id:
        return no_member_id

    # Check whether account actually exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the member account to delete.", "error")
        logger.error(f"Admin '{current_user.username}' tried delete the member without providing the id for an existing account")
        return redirect(url_for("member_control_bp.view_member_details"))

    form = LockDeleteMemberForm()
    if request.method == "POST" and form.validate_on_submit():
        # Sanitise inputs
        reason = clean_input(form.reason.data)
        admin_key = clean_input(form.admin_key.data)

        # Check valid admin key
        not_valid_admin_key = check_admin_key(admin_key, current_user, fallback_endpoint="member_control_bp.delete_member")
        if not_valid_admin_key:
            return not_valid_admin_key
        
        # Try sending email using utility send_email function
        email_body = f"Your account has been deleted. The reason is:\n{reason}"
        if send_email(member.email, "Deleted Account", email_body):
            Member.delete(member_id)
            clear_unwanted_session_keys(ESSENTIAL_KEYS)
            flash("Successfully deleted member account!", "success")
            logger.info(f"Admin '{current_user.username}' successfully deleted member with member id of '{id}'")
            return redirect(url_for("member_control_bp.view_members"))
        else:
            flash("An error occurred while deleting the account.")
            logger.error(f"Failed to send email to inform member '{member.username}' that their account has been deleted.")
            return redirect(url_for("member_control_bp.view_member_details"))
    
    # Render the delete member template
    return render_template(f"{TEMPLATE_FOLDER}/delete_member.html", form=form)


# Send reset password link route
@member_control_bp.route("/view/send_password_link", methods=['GET'])
@login_required
def send_password_link():
    # Check if user is admin
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Check member_id exists in session
    no_member_id_in_session = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_members',
        flash_message="No member selected. Please select a member from the list.",
        log_message=f"Admin '{current_user.username}' attempted to view member details without selecting a member.",
        keys_to_keep=ESSENTIAL_KEYS
    )
    if no_member_id_in_session:
        return no_member_id_in_session
    
    # Check whether member in session
    no_member_id = check_session_keys(
        required_keys=['member_id'],
        fallback_endpoint='member_control_bp.view_member_details',
        flash_message='There is no member account selected to send reset password link to. Please choose an member account.',
        log_message='User tried to send reset password link to a member\'s email without providing the account id.',
        keys_to_keep=MEMBER_SPECIFIC_ESSENTIAL_KEYS
    )
    if no_member_id:
        return no_member_id

    # Check whether account actually exists
    member_id = session.get("member_id")
    member = Member.query.get(member_id)
    if not member:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("Couldn't find the member account to delete.", "error")
        logger.error(f"Admin '{current_user.username}' tried delete the member without providing the id for an existing account")
        return redirect(url_for("member_control_bp.view_member_details"))

    # Generate secure token for password reset
    email = member.email
    token = PasswordResetToken.create(email=email)
    reset_url = url_for('recovery_auth_bp.reset_password', token=token, _external=True)

    # Try sending email using utility send_email function
    email_body = f'Click the link to reset your password: <a href="{reset_url}" rel="noreferrer">{reset_url}</a>'
    if send_email(email, "Password Reset Request", email_body):
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        response = redirect(url_for("member_control_bp.view_member_details"))
        unset_jwt_cookies(response)
        flash("A password reset link has been sent!", "success")
        logger.info(f"Password reset link sent to {email}")
        return response
    else:
        clear_unwanted_session_keys(MEMBER_SPECIFIC_ESSENTIAL_KEYS)
        flash("An error occurred while sending the password reset link. Please try again.", "error")
        logger.error(f"Failed to send password reset link to {email}")
        return redirect(url_for("member_control_bp.view_member_details"))

